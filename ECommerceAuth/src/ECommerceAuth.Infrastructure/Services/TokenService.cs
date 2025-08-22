using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using ECommerceAuth.Application.Interfaces;
using ECommerceAuth.Domain.Entities;
using ECommerceAuth.Infrastructure.Data;
using OtpNet;
using QRCoder;

namespace ECommerceAuth.Infrastructure.Services
{
    /// <summary>
    /// Service de gestion des tokens JWT et de l'authentification 2FA.
    /// </summary>
    /// <remarks>
    /// Ce service implémente toutes les fonctionnalités liées aux tokens :
    /// - Génération et validation des JWT d'accès
    /// - Gestion des refresh tokens avec stockage sécurisé
    /// - Authentification à deux facteurs (TOTP)
    /// - Nettoyage automatique des tokens expirés
    /// 
    /// Sécurité implémentée :
    /// - JWT signés avec HMAC SHA-256 et clé secrète forte
    /// - Refresh tokens générés cryptographiquement sécurisés
    /// - Durées de vie configurables et appropriées
    /// - Révocation côté serveur pour invalidation immédiate
    /// - Support TOTP compatible Google Authenticator
    /// </remarks>
    public class TokenService : ITokenService
    {
        private readonly ECommerceAuthDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<TokenService> _logger;
        private readonly string _jwtSecret;
        private readonly string _jwtIssuer;
        private readonly string _jwtAudience;
        private readonly int _accessTokenExpirationMinutes;
        private readonly int _refreshTokenExpirationDays;
        private readonly int _refreshTokenExpirationDaysRememberMe;

        public TokenService(
            ECommerceAuthDbContext context,
            IConfiguration configuration,
            ILogger<TokenService> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;

            // Configuration JWT depuis appsettings.json
            _jwtSecret = _configuration["Jwt:Secret"] ?? throw new InvalidOperationException("JWT Secret non configuré");
            _jwtIssuer = _configuration["Jwt:Issuer"] ?? "ECommerceAuth";
            _jwtAudience = _configuration["Jwt:Audience"] ?? "ECommerceAuth";
            _accessTokenExpirationMinutes = int.Parse(_configuration["Jwt:AccessTokenExpirationMinutes"] ?? "30");
            _refreshTokenExpirationDays = int.Parse(_configuration["Jwt:RefreshTokenExpirationDays"] ?? "7");
            _refreshTokenExpirationDaysRememberMe = int.Parse(_configuration["Jwt:RefreshTokenExpirationDaysRememberMe"] ?? "30");

            // Validation de la sécurité de la clé
            if (_jwtSecret.Length < 32)
            {
                throw new InvalidOperationException("La clé JWT doit faire au moins 32 caractères pour la sécurité");
            }
        }

        /// <summary>
        /// Génère un token JWT d'accès sécurisé pour un utilisateur.
        /// </summary>
        public async Task<string> GenerateAccessTokenAsync(User user, IEnumerable<string> roles)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSecret);
            
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new(ClaimTypes.Name, user.UserName),
                new(ClaimTypes.Email, user.Email),
                new("jti", Guid.NewGuid().ToString()), // JWT ID pour l'unicité
                new("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            // Ajout des rôles comme claims
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_accessTokenExpirationMinutes),
                Issuer = _jwtIssuer,
                Audience = _jwtAudience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            _logger.LogInformation("Token JWT généré pour l'utilisateur {UserId}", user.Id);
            
            return await Task.FromResult(tokenString);
        }

        /// <summary>
        /// Génère un refresh token cryptographiquement sécurisé.
        /// </summary>
        public async Task<RefreshToken> GenerateRefreshTokenAsync(Guid userId, string ipAddress, string? userAgent = null, bool rememberMe = false)
        {
            using var rng = RandomNumberGenerator.Create();
            var randomBytes = new byte[64];
            rng.GetBytes(randomBytes);
            var token = Convert.ToBase64String(randomBytes);

            var expirationDays = rememberMe ? _refreshTokenExpirationDaysRememberMe : _refreshTokenExpirationDays;
            var expiresAt = DateTime.UtcNow.AddDays(expirationDays);

            var refreshToken = new RefreshToken(userId, token, expiresAt, ipAddress, userAgent);

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Refresh token généré pour l'utilisateur {UserId}, expire le {ExpiresAt}", userId, expiresAt);

            return refreshToken;
        }

        /// <summary>
        /// Valide un token JWT et retourne les claims.
        /// </summary>
        public ClaimsPrincipal? ValidateToken(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_jwtSecret);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _jwtIssuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtAudience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero // Pas de tolérance pour l'expiration
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
                return principal;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Échec de validation du token JWT : {Error}", ex.Message);
                return null;
            }
        }

        /// <summary>
        /// Extrait l'ID utilisateur d'un token JWT.
        /// </summary>
        public Guid? GetUserIdFromToken(string token)
        {
            var principal = ValidateToken(token);
            var userIdClaim = principal?.FindFirst(ClaimTypes.NameIdentifier);
            
            if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
            {
                return userId;
            }

            return null;
        }

        /// <summary>
        /// Extrait les rôles d'un token JWT.
        /// </summary>
        public IEnumerable<string> GetRolesFromToken(string token)
        {
            var principal = ValidateToken(token);
            if (principal == null) return new List<string>();

            return principal.FindAll(ClaimTypes.Role).Select(c => c.Value);
        }

        /// <summary>
        /// Vérifie si un token JWT est expiré.
        /// </summary>
        public bool IsTokenExpired(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jsonToken = tokenHandler.ReadJwtToken(token);
                
                return jsonToken.ValidTo < DateTime.UtcNow;
            }
            catch
            {
                return true; // Si on ne peut pas lire le token, on le considère comme expiré
            }
        }

        /// <summary>
        /// Révoque un refresh token spécifique.
        /// </summary>
        public async Task<bool> RevokeRefreshTokenAsync(string token, string reason, string? revokedByIp = null)
        {
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == token && !rt.IsRevoked);

            if (refreshToken == null)
            {
                _logger.LogWarning("Tentative de révocation d'un token inexistant ou déjà révoqué : {Token}", token[..10] + "...");
                return false;
            }

            refreshToken.Revoke(revokedByIp, reason);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Refresh token révoqué pour l'utilisateur {UserId}, raison : {Reason}", refreshToken.UserId, reason);
            
            return true;
        }

        /// <summary>
        /// Révoque tous les refresh tokens d'un utilisateur.
        /// </summary>
        public async Task<int> RevokeAllUserTokensAsync(Guid userId, string reason, string? revokedByIp = null)
        {
            var activeTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && !rt.IsRevoked && rt.ExpiresAt > DateTime.UtcNow)
                .ToListAsync();

            foreach (var token in activeTokens)
            {
                token.Revoke(revokedByIp, reason);
            }

            await _context.SaveChangesAsync();

            _logger.LogInformation("{Count} refresh tokens révoqués pour l'utilisateur {UserId}", activeTokens.Count, userId);
            
            return activeTokens.Count;
        }

        /// <summary>
        /// Nettoie les tokens expirés et révoqués de la base de données.
        /// </summary>
        public async Task<int> CleanupExpiredTokensAsync()
        {
            var expiredTokens = await _context.RefreshTokens
                .Where(rt => rt.ExpiresAt < DateTime.UtcNow || rt.IsRevoked)
                .Where(rt => rt.CreatedAt < DateTime.UtcNow.AddDays(-30)) // Garder 30 jours pour audit
                .ToListAsync();

            _context.RefreshTokens.RemoveRange(expiredTokens);
            await _context.SaveChangesAsync();

            _logger.LogInformation("{Count} tokens expirés supprimés de la base de données", expiredTokens.Count);
            
            return expiredTokens.Count;
        }

        /// <summary>
        /// Obtient un refresh token actif par sa valeur.
        /// </summary>
        public async Task<RefreshToken?> GetActiveRefreshTokenAsync(string token)
        {
            return await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == token && rt.IsActive);
        }

        /// <summary>
        /// Compte le nombre de tokens actifs pour un utilisateur.
        /// </summary>
        public async Task<int> CountActiveTokensAsync(Guid userId)
        {
            return await _context.RefreshTokens
                .CountAsync(rt => rt.UserId == userId && rt.IsActive);
        }

        /// <summary>
        /// Génère une clé secrète pour l'authentification 2FA.
        /// </summary>
        public string GenerateTwoFactorSecret()
        {
            var key = KeyGeneration.GenerateRandomKey(20); // 160 bits recommandés pour TOTP
            return Base32Encoding.ToString(key);
        }

        /// <summary>
        /// Génère un QR code pour configurer l'authentification 2FA.
        /// </summary>
        public string GenerateTwoFactorQrCode(string email, string secret, string issuer = "ECommerce Auth")
        {
            var totpUri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";
            
            using var qrGenerator = new QRCodeGenerator();
            var qrCodeData = qrGenerator.CreateQrCode(totpUri, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new Base64QRCode(qrCodeData);
            
            return qrCode.GetGraphic(20); // Taille du QR code
        }

        /// <summary>
        /// Valide un code d'authentification à deux facteurs.
        /// </summary>
        public bool ValidateTwoFactorCode(string secret, string code)
        {
            try
            {
                var secretBytes = Base32Encoding.ToBytes(secret);
                var totp = new Totp(secretBytes);
                
                // Vérifier le code actuel et les codes des 30 secondes précédentes/suivantes
                // pour compenser les décalages d'horloge
                return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la validation du code 2FA");
                return false;
            }
        }
    }
}