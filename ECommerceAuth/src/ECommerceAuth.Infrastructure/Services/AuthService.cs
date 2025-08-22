using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using BCrypt.Net;
using ECommerceAuth.Application.Interfaces;
using ECommerceAuth.Application.DTOs.Auth;
using ECommerceAuth.Domain.Entities;
using ECommerceAuth.Domain.Enums;
using ECommerceAuth.Infrastructure.Data;

namespace ECommerceAuth.Infrastructure.Services
{
    /// <summary>
    /// Service d'authentification implémentant toutes les opérations liées aux utilisateurs.
    /// </summary>
    public class AuthService : IAuthService
    {
        private readonly ECommerceAuthDbContext _context;
        private readonly ITokenService _tokenService;
        private readonly IEmailService _emailService;
        private readonly ILogger<AuthService> _logger;
        private readonly IConfiguration _configuration;

        public AuthService(
            ECommerceAuthDbContext context,
            ITokenService tokenService,
            IEmailService emailService,
            ILogger<AuthService> logger,
            IConfiguration configuration)
        {
            _context = context;
            _tokenService = tokenService;
            _emailService = emailService;
            _logger = logger;
            _configuration = configuration;
        }

        public async Task<AuthResult> RegisterAsync(RegisterRequestDto request, string ipAddress, string? userAgent = null)
        {
            try
            {
                // Check if user already exists
                if (await _context.Users.AnyAsync(u => u.Email == request.Email))
                {
                    return AuthResult.FailureResult("Un compte avec cet email existe déjà");
                }

                if (await _context.Users.AnyAsync(u => u.UserName == request.UserName))
                {
                    return AuthResult.FailureResult("Ce nom d'utilisateur est déjà pris");
                }

                // Create new user
                var user = new User
                {
                    UserName = request.UserName,
                    Email = request.Email,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
                    FirstName = request.FirstName,
                    LastName = request.LastName,
                    PhoneNumber = request.PhoneNumber,
                    EmailConfirmationToken = Guid.NewGuid().ToString(),
                    EmailConfirmationTokenExpiry = DateTime.UtcNow.AddHours(72),
                    IsActive = true
                };

                _context.Users.Add(user);

                // Assign role
                var role = await _context.Roles.FirstOrDefaultAsync(r => r.Name == request.Role.ToString());
                if (role != null)
                {
                    var userRole = new UserRole(user.Id, role.Id);
                    _context.UserRoles.Add(userRole);
                }

                await _context.SaveChangesAsync();

                // Send confirmation email
                var confirmationLink = $"{_configuration["Application:BaseUrl"]}/api/auth/confirm-email?userId={user.Id}&token={user.EmailConfirmationToken}";
                await _emailService.SendEmailConfirmationAsync(user.Email, user.UserName, confirmationLink);

                _logger.LogInformation("Utilisateur créé avec succès: {Email}", request.Email);

                return AuthResult.SuccessResult("Inscription réussie. Veuillez vérifier votre email pour confirmer votre compte.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'inscription: {Email}", request.Email);
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<AuthResult> LoginAsync(LoginRequestDto request, string ipAddress, string? userAgent = null)
        {
            try
            {
                var user = await _context.Users
                    .Include(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                    .FirstOrDefaultAsync(u => u.Email == request.Email);

                if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    // Log failed attempt
                    var loginHistory = new LoginHistory(Guid.Empty, ipAddress, userAgent, false, "Identifiants incorrects");
                    _context.LoginHistories.Add(loginHistory);
                    await _context.SaveChangesAsync();

                    return AuthResult.FailureResult("Email ou mot de passe incorrect");
                }

                // Check if account is locked
                if (user.IsLockedOut)
                {
                    return AuthResult.FailureResult($"Compte verrouillé jusqu'à {user.LockoutEnd:yyyy-MM-dd HH:mm}");
                }

                // Check if email is confirmed
                if (!user.EmailConfirmed)
                {
                    return AuthResult.FailureResult("Veuillez confirmer votre email avant de vous connecter");
                }

                // Check if 2FA is required
                if (user.TwoFactorEnabled && string.IsNullOrEmpty(request.TwoFactorCode))
                {
                    return AuthResult.TwoFactorRequiredResult("Code d'authentification à deux facteurs requis");
                }

                // Verify 2FA code if provided
                if (user.TwoFactorEnabled && !string.IsNullOrEmpty(request.TwoFactorCode))
                {
                    if (!_tokenService.ValidateTwoFactorCode(user.TwoFactorSecretKey!, request.TwoFactorCode))
                    {
                        return AuthResult.FailureResult("Code 2FA invalide");
                    }
                }

                // Generate tokens
                var roles = user.UserRoles.Select(ur => ur.Role.Name).ToList();
                var accessToken = _tokenService.GenerateAccessToken(user, roles);
                var refreshToken = await _tokenService.GenerateRefreshTokenAsync(user.Id, ipAddress, userAgent, request.RememberMe);

                // Update user login info
                user.LastLoginAt = DateTime.UtcNow;
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;

                // Log successful login
                var successLoginHistory = new LoginHistory(user.Id, ipAddress, userAgent, true);
                _context.LoginHistories.Add(successLoginHistory);

                await _context.SaveChangesAsync();

                var response = new AuthResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken.Token,
                    ExpiresIn = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "30") * 60,
                    User = new UserInfoDto
                    {
                        Id = user.Id,
                        UserName = user.UserName,
                        Email = user.Email,
                        FirstName = user.FirstName,
                        LastName = user.LastName,
                        AvatarUrl = user.AvatarUrl,
                        EmailConfirmed = user.EmailConfirmed,
                        TwoFactorEnabled = user.TwoFactorEnabled,
                        LastLoginAt = user.LastLoginAt
                    },
                    Roles = roles,
                    AccessTokenExpiry = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "30")),
                    RefreshTokenExpiry = refreshToken.ExpiresAt
                };

                return AuthResult.SuccessResult("Connexion réussie", response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la connexion: {Email}", request.Email);
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<AuthResult> RefreshTokenAsync(string refreshToken, string ipAddress, string? userAgent = null)
        {
            try
            {
                var token = await _context.RefreshTokens
                    .Include(rt => rt.User)
                    .ThenInclude(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
                    .FirstOrDefaultAsync(rt => rt.Token == refreshToken);

                if (token == null || token.IsRevoked || token.ExpiresAt <= DateTime.UtcNow)
                {
                    return AuthResult.FailureResult("Token de rafraîchissement invalide ou expiré");
                }

                // Generate new tokens
                var roles = token.User.UserRoles.Select(ur => ur.Role.Name).ToList();
                var newAccessToken = _tokenService.GenerateAccessToken(token.User, roles);
                var newRefreshToken = await _tokenService.GenerateRefreshTokenAsync(token.User.Id, ipAddress, userAgent);

                // Revoke old token
                token.Revoke(ipAddress, "Remplacé par un nouveau token");
                await _context.SaveChangesAsync();

                var response = new AuthResponseDto
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken.Token,
                    ExpiresIn = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "30") * 60,
                    User = new UserInfoDto
                    {
                        Id = token.User.Id,
                        UserName = token.User.UserName,
                        Email = token.User.Email,
                        FirstName = token.User.FirstName,
                        LastName = token.User.LastName,
                        AvatarUrl = token.User.AvatarUrl,
                        EmailConfirmed = token.User.EmailConfirmed,
                        TwoFactorEnabled = token.User.TwoFactorEnabled,
                        LastLoginAt = token.User.LastLoginAt
                    },
                    Roles = roles,
                    AccessTokenExpiry = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "30")),
                    RefreshTokenExpiry = newRefreshToken.ExpiresAt
                };

                return AuthResult.SuccessResult("Token rafraîchi avec succès", response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors du rafraîchissement du token");
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<AuthResult> LogoutAsync(string refreshToken, string ipAddress)
        {
            try
            {
                await _tokenService.RevokeRefreshTokenAsync(refreshToken, "Déconnexion utilisateur", ipAddress);
                return AuthResult.SuccessResult("Déconnexion réussie");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la déconnexion");
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<AuthResult> ConfirmEmailAsync(Guid userId, string token)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return AuthResult.FailureResult("Utilisateur non trouvé");
                }

                if (user.EmailConfirmationToken != token || user.EmailConfirmationTokenExpiry <= DateTime.UtcNow)
                {
                    return AuthResult.FailureResult("Token de confirmation invalide ou expiré");
                }

                user.EmailConfirmed = true;
                user.EmailConfirmationToken = null;
                user.EmailConfirmationTokenExpiry = null;

                await _context.SaveChangesAsync();

                return AuthResult.SuccessResult("Email confirmé avec succès");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la confirmation d'email");
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<AuthResult> ForgotPasswordAsync(string email)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null)
                {
                    // Don't reveal if user exists
                    return AuthResult.SuccessResult("Si un compte avec cet email existe, un lien de réinitialisation a été envoyé");
                }

                user.PasswordResetToken = Guid.NewGuid().ToString();
                user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(24);

                await _context.SaveChangesAsync();

                var resetLink = $"{_configuration["Application:BaseUrl"]}/reset-password?email={email}&token={user.PasswordResetToken}";
                await _emailService.SendPasswordResetAsync(email, user.UserName, resetLink);

                return AuthResult.SuccessResult("Si un compte avec cet email existe, un lien de réinitialisation a été envoyé");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la demande de réinitialisation de mot de passe");
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<AuthResult> ResetPasswordAsync(string email, string token, string newPassword)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null || user.PasswordResetToken != token || user.PasswordResetTokenExpiry <= DateTime.UtcNow)
                {
                    return AuthResult.FailureResult("Token de réinitialisation invalide ou expiré");
                }

                user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);
                user.PasswordResetToken = null;
                user.PasswordResetTokenExpiry = null;

                await _context.SaveChangesAsync();

                return AuthResult.SuccessResult("Mot de passe réinitialisé avec succès");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la réinitialisation du mot de passe");
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<AuthResult> EnableTwoFactorAsync(Guid userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return AuthResult.FailureResult("Utilisateur non trouvé");
                }

                var secretKey = _tokenService.GenerateTwoFactorSecretKey();
                user.TwoFactorSecretKey = secretKey;
                user.TwoFactorEnabled = true;

                await _context.SaveChangesAsync();

                var qrCodeUrl = _tokenService.GenerateTwoFactorQrCode(user.Email, secretKey);

                var result = AuthResult.SuccessResult("2FA activé avec succès");
                result.AdditionalData["SecretKey"] = secretKey;
                result.AdditionalData["QrCodeUrl"] = qrCodeUrl;

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'activation du 2FA");
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<AuthResult> DisableTwoFactorAsync(Guid userId, string code)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null)
                {
                    return AuthResult.FailureResult("Utilisateur non trouvé");
                }

                if (!_tokenService.ValidateTwoFactorCode(user.TwoFactorSecretKey!, code))
                {
                    return AuthResult.FailureResult("Code 2FA invalide");
                }

                user.TwoFactorEnabled = false;
                user.TwoFactorSecretKey = null;

                await _context.SaveChangesAsync();

                return AuthResult.SuccessResult("2FA désactivé avec succès");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la désactivation du 2FA");
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }

        public async Task<bool> UserExistsAsync(string email)
        {
            return await _context.Users.AnyAsync(u => u.Email == email);
        }

        public async Task<AuthResult> RevokeAllTokensAsync(Guid userId, string reason)
        {
            try
            {
                await _tokenService.RevokeAllUserTokensAsync(userId, reason);
                return AuthResult.SuccessResult("Tous les tokens ont été révoqués");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la révocation des tokens");
                return AuthResult.FailureResult("Une erreur interne s'est produite");
            }
        }
    }
}