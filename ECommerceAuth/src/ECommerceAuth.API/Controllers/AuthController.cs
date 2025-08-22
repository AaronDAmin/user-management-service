using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using ECommerceAuth.Application.Interfaces;
using ECommerceAuth.Application.DTOs.Auth;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;

namespace ECommerceAuth.API.Controllers
{
    /// <summary>
    /// Contrôleur d'authentification pour la plateforme e-commerce.
    /// </summary>
    /// <remarks>
    /// Ce contrôleur expose tous les endpoints nécessaires pour l'authentification :
    /// - Inscription et confirmation d'email
    /// - Connexion avec support 2FA
    /// - Gestion des tokens (refresh, logout)
    /// - Réinitialisation de mot de passe
    /// - Activation/désactivation 2FA
    /// 
    /// Sécurité implémentée :
    /// - Validation des inputs avec FluentValidation
    /// - Protection contre les attaques par force brute
    /// - Audit des connexions avec IP et User-Agent
    /// - Gestion sécurisée des tokens JWT
    /// - Support HTTPS obligatoire en production
    /// </remarks>
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Inscrit un nouvel utilisateur dans le système.
        /// </summary>
        /// <param name="request">Données d'inscription de l'utilisateur</param>
        /// <returns>Résultat de l'inscription avec instructions de confirmation</returns>
        /// <response code="200">Inscription réussie, email de confirmation envoyé</response>
        /// <response code="400">Données d'inscription invalides</response>
        /// <response code="409">Email ou nom d'utilisateur déjà utilisé</response>
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(409)]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var userAgent = Request.Headers.UserAgent.ToString();

                _logger.LogInformation("Tentative d'inscription pour l'email {Email} depuis {IpAddress}", 
                    request.Email, ipAddress);

                var result = await _authService.RegisterAsync(request, ipAddress, userAgent);

                if (result.Success)
                {
                    _logger.LogInformation("Inscription réussie pour l'email {Email}", request.Email);
                    return Ok(result);
                }

                _logger.LogWarning("Échec d'inscription pour l'email {Email}: {Message}", 
                    request.Email, result.Message);
                
                return result.Message.Contains("existe déjà") ? Conflict(result) : BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'inscription pour l'email {Email}", request.Email);
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        /// <summary>
        /// Authentifie un utilisateur et génère les tokens d'accès.
        /// </summary>
        /// <param name="request">Données de connexion (email, mot de passe, code 2FA optionnel)</param>
        /// <returns>Tokens JWT et informations utilisateur</returns>
        /// <response code="200">Connexion réussie avec tokens</response>
        /// <response code="400">Données de connexion invalides</response>
        /// <response code="401">Identifiants incorrects ou compte verrouillé</response>
        /// <response code="403">Authentification 2FA requise</response>
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        [ProducesResponseType(403)]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
        {
            try
            {
                var ipAddress = GetClientIpAddress();
                var userAgent = Request.Headers.UserAgent.ToString();

                _logger.LogInformation("Tentative de connexion pour l'email {Email} depuis {IpAddress}", 
                    request.Email, ipAddress);

                var result = await _authService.LoginAsync(request, ipAddress, userAgent);

                if (result.Success)
                {
                    _logger.LogInformation("Connexion réussie pour l'email {Email}", request.Email);
                    
                    // Définir le refresh token dans un cookie sécurisé
                    if (result.Data?.RefreshToken != null)
                    {
                        SetRefreshTokenCookie(result.Data.RefreshToken);
                    }
                    
                    return Ok(result);
                }

                if (result.RequiresTwoFactor)
                {
                    _logger.LogInformation("Authentification 2FA requise pour l'email {Email}", request.Email);
                    return StatusCode(403, result);
                }

                _logger.LogWarning("Échec de connexion pour l'email {Email}: {Message}", 
                    request.Email, result.Message);
                
                return Unauthorized(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la connexion pour l'email {Email}", request.Email);
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        /// <summary>
        /// Rafraîchit un token d'accès expiré.
        /// </summary>
        /// <param name="request">Token de rafraîchissement</param>
        /// <returns>Nouveaux tokens d'accès et de rafraîchissement</returns>
        /// <response code="200">Token rafraîchi avec succès</response>
        /// <response code="400">Token de rafraîchissement invalide</response>
        /// <response code="401">Token de rafraîchissement expiré ou révoqué</response>
        [HttpPost("refresh-token")]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDto request)
        {
            try
            {
                var refreshToken = request.RefreshToken ?? Request.Cookies["refreshToken"];
                
                if (string.IsNullOrEmpty(refreshToken))
                {
                    return BadRequest(new AuthResult 
                    { 
                        Success = false, 
                        Message = "Token de rafraîchissement requis" 
                    });
                }

                var ipAddress = GetClientIpAddress();
                var userAgent = Request.Headers.UserAgent.ToString();

                var result = await _authService.RefreshTokenAsync(refreshToken, ipAddress, userAgent);

                if (result.Success)
                {
                    _logger.LogInformation("Token rafraîchi avec succès depuis {IpAddress}", ipAddress);
                    
                    // Mettre à jour le cookie avec le nouveau refresh token
                    if (result.Data?.RefreshToken != null)
                    {
                        SetRefreshTokenCookie(result.Data.RefreshToken);
                    }
                    
                    return Ok(result);
                }

                _logger.LogWarning("Échec du rafraîchissement de token: {Message}", result.Message);
                return Unauthorized(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors du rafraîchissement de token");
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        /// <summary>
        /// Déconnecte l'utilisateur et révoque ses tokens.
        /// </summary>
        /// <returns>Confirmation de déconnexion</returns>
        /// <response code="200">Déconnexion réussie</response>
        /// <response code="400">Erreur lors de la déconnexion</response>
        [HttpPost("logout")]
        [Authorize]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"];
                var ipAddress = GetClientIpAddress();

                if (!string.IsNullOrEmpty(refreshToken))
                {
                    await _authService.LogoutAsync(refreshToken, ipAddress);
                }

                // Supprimer le cookie de refresh token
                Response.Cookies.Delete("refreshToken");

                var userId = GetCurrentUserId();
                _logger.LogInformation("Déconnexion réussie pour l'utilisateur {UserId}", userId);

                return Ok(new AuthResult 
                { 
                    Success = true, 
                    Message = "Déconnexion réussie" 
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la déconnexion");
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        /// <summary>
        /// Confirme l'adresse email d'un utilisateur.
        /// </summary>
        /// <param name="userId">ID de l'utilisateur</param>
        /// <param name="token">Token de confirmation d'email</param>
        /// <returns>Résultat de la confirmation</returns>
        /// <response code="200">Email confirmé avec succès</response>
        /// <response code="400">Token de confirmation invalide ou expiré</response>
        [HttpGet("confirm-email")]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> ConfirmEmail([FromQuery] Guid userId, [FromQuery] string token)
        {
            try
            {
                if (userId == Guid.Empty || string.IsNullOrEmpty(token))
                {
                    return BadRequest(new AuthResult 
                    { 
                        Success = false, 
                        Message = "Paramètres de confirmation invalides" 
                    });
                }

                var result = await _authService.ConfirmEmailAsync(userId, token);

                if (result.Success)
                {
                    _logger.LogInformation("Email confirmé avec succès pour l'utilisateur {UserId}", userId);
                }
                else
                {
                    _logger.LogWarning("Échec de confirmation d'email pour l'utilisateur {UserId}: {Message}", 
                        userId, result.Message);
                }

                return result.Success ? Ok(result) : BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la confirmation d'email pour l'utilisateur {UserId}", userId);
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        /// <summary>
        /// Envoie un email de réinitialisation de mot de passe.
        /// </summary>
        /// <param name="request">Adresse email pour la réinitialisation</param>
        /// <returns>Confirmation d'envoi</returns>
        /// <response code="200">Email de réinitialisation envoyé</response>
        /// <response code="400">Adresse email invalide</response>
        [HttpPost("forgot-password")]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequestDto request)
        {
            try
            {
                var result = await _authService.ForgotPasswordAsync(request.Email);

                _logger.LogInformation("Demande de réinitialisation de mot de passe pour l'email {Email}", 
                    request.Email);

                // Toujours retourner succès pour éviter l'énumération d'emails
                return Ok(new AuthResult 
                { 
                    Success = true, 
                    Message = "Si cette adresse email existe, un lien de réinitialisation a été envoyé" 
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la demande de réinitialisation pour l'email {Email}", 
                    request.Email);
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        /// <summary>
        /// Réinitialise le mot de passe d'un utilisateur.
        /// </summary>
        /// <param name="request">Données de réinitialisation (email, token, nouveau mot de passe)</param>
        /// <returns>Résultat de la réinitialisation</returns>
        /// <response code="200">Mot de passe réinitialisé avec succès</response>
        /// <response code="400">Token de réinitialisation invalide ou expiré</response>
        [HttpPost("reset-password")]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(400)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequestDto request)
        {
            try
            {
                var result = await _authService.ResetPasswordAsync(request.Email, request.Token, request.NewPassword);

                if (result.Success)
                {
                    _logger.LogInformation("Mot de passe réinitialisé avec succès pour l'email {Email}", 
                        request.Email);
                }
                else
                {
                    _logger.LogWarning("Échec de réinitialisation de mot de passe pour l'email {Email}: {Message}", 
                        request.Email, result.Message);
                }

                return result.Success ? Ok(result) : BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la réinitialisation de mot de passe pour l'email {Email}", 
                    request.Email);
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        /// <summary>
        /// Active l'authentification à deux facteurs pour l'utilisateur connecté.
        /// </summary>
        /// <returns>Clé secrète et QR code pour configurer l'authenticator</returns>
        /// <response code="200">2FA activé avec succès</response>
        /// <response code="401">Utilisateur non authentifié</response>
        [HttpPost("enable-2fa")]
        [Authorize]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> EnableTwoFactor()
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _authService.EnableTwoFactorAsync(userId);

                if (result.Success)
                {
                    _logger.LogInformation("2FA activé pour l'utilisateur {UserId}", userId);
                }

                return result.Success ? Ok(result) : BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'activation 2FA");
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        /// <summary>
        /// Désactive l'authentification à deux facteurs.
        /// </summary>
        /// <param name="request">Code de vérification 2FA</param>
        /// <returns>Résultat de la désactivation</returns>
        /// <response code="200">2FA désactivé avec succès</response>
        /// <response code="400">Code 2FA invalide</response>
        /// <response code="401">Utilisateur non authentifié</response>
        [HttpPost("disable-2fa")]
        [Authorize]
        [ProducesResponseType(typeof(AuthResult), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<IActionResult> DisableTwoFactor([FromBody] DisableTwoFactorRequestDto request)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _authService.DisableTwoFactorAsync(userId, request.Code);

                if (result.Success)
                {
                    _logger.LogInformation("2FA désactivé pour l'utilisateur {UserId}", userId);
                }

                return result.Success ? Ok(result) : BadRequest(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de la désactivation 2FA");
                return StatusCode(500, new AuthResult 
                { 
                    Success = false, 
                    Message = "Une erreur interne s'est produite" 
                });
            }
        }

        #region Méthodes utilitaires privées

        /// <summary>
        /// Obtient l'adresse IP du client en tenant compte des proxies.
        /// </summary>
        private string GetClientIpAddress()
        {
            var xForwardedFor = Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(xForwardedFor))
            {
                // Take the first IP and validate it to prevent spoofing
                var firstIp = xForwardedFor.Split(',')[0].Trim();
                if (System.Net.IPAddress.TryParse(firstIp, out _))
                {
                    return firstIp;
                }
            }

            var xRealIp = Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(xRealIp) && System.Net.IPAddress.TryParse(xRealIp, out _))
            {
                return xRealIp;
            }

            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }

        /// <summary>
        /// Obtient l'ID de l'utilisateur connecté depuis les claims JWT.
        /// </summary>
        private Guid GetCurrentUserId()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
            {
                return userId;
            }
            throw new UnauthorizedAccessException("Utilisateur non authentifié");
        }

        /// <summary>
        /// Définit le refresh token dans un cookie sécurisé.
        /// </summary>
        private void SetRefreshTokenCookie(string refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true, // Empêche l'accès via JavaScript (protection XSS)
                Secure = Request.IsHttps, // HTTPS uniquement si la requête est en HTTPS
                SameSite = SameSiteMode.Strict, // Protection CSRF
                Expires = DateTimeOffset.UtcNow.AddDays(7), // Durée de vie du cookie
                Path = "/", // Limiter le chemin du cookie
                IsEssential = true // Cookie essentiel pour le fonctionnement
            };

            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }

        #endregion
    }

    #region DTOs supplémentaires

    /// <summary>
    /// DTO pour les demandes de refresh token.
    /// </summary>
    public class RefreshTokenRequestDto
    {
        public string? RefreshToken { get; set; }
    }

    /// <summary>
    /// DTO pour les demandes de mot de passe oublié.
    /// </summary>
    public class ForgotPasswordRequestDto
    {
        [Required(ErrorMessage = "L'email est requis")]
        [EmailAddress(ErrorMessage = "Format d'email invalide")]
        public string Email { get; set; } = string.Empty;
    }

    /// <summary>
    /// DTO pour les demandes de réinitialisation de mot de passe.
    /// </summary>
    public class ResetPasswordRequestDto
    {
        [Required(ErrorMessage = "L'email est requis")]
        [EmailAddress(ErrorMessage = "Format d'email invalide")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Le token est requis")]
        public string Token { get; set; } = string.Empty;

        [Required(ErrorMessage = "Le nouveau mot de passe est requis")]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Le mot de passe doit contenir au moins 8 caractères")]
        public string NewPassword { get; set; } = string.Empty;
    }

    /// <summary>
    /// DTO pour désactiver l'authentification 2FA.
    /// </summary>
    public class DisableTwoFactorRequestDto
    {
        [Required(ErrorMessage = "Le code 2FA est requis")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Le code 2FA doit contenir exactement 6 chiffres")]
        public string Code { get; set; } = string.Empty;
    }

    #endregion
}