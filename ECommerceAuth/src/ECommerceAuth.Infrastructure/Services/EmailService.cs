using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using ECommerceAuth.Application.Interfaces;

namespace ECommerceAuth.Infrastructure.Services
{
    /// <summary>
    /// Service d'envoi d'emails implémentant toutes les fonctionnalités de communication par email.
    /// </summary>
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        private readonly string _smtpHost;
        private readonly int _smtpPort;
        private readonly string _smtpUsername;
        private readonly string _smtpPassword;
        private readonly string _fromEmail;
        private readonly string _fromName;
        private readonly bool _enableSsl;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;

            _smtpHost = _configuration["Email:SmtpHost"] ?? "smtp.gmail.com";
            _smtpPort = int.TryParse(_configuration["Email:SmtpPort"], out var port) ? port : 587;
            _smtpUsername = Environment.GetEnvironmentVariable("SMTP_USERNAME") ?? _configuration["Email:SmtpUsername"] ?? "";
            _smtpPassword = Environment.GetEnvironmentVariable("SMTP_PASSWORD") ?? _configuration["Email:SmtpPassword"] ?? "";
            _fromEmail = _configuration["Email:FromEmail"] ?? "noreply@ecommerceauth.com";
            _fromName = _configuration["Email:FromName"] ?? "ECommerce Auth";
            _enableSsl = bool.TryParse(_configuration["Email:EnableSsl"], out var ssl) ? ssl : true;
        }

        public async Task<bool> SendEmailConfirmationAsync(string email, string userName, string confirmationLink)
        {
            try
            {
                var subject = "Confirmez votre adresse email";
                var body = $@"
                    <h2>Bienvenue {userName}!</h2>
                    <p>Merci de vous être inscrit sur notre plateforme e-commerce.</p>
                    <p>Pour activer votre compte, veuillez cliquer sur le lien ci-dessous :</p>
                    <p><a href='{confirmationLink}' style='background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Confirmer mon email</a></p>
                    <p>Ce lien expirera dans 72 heures.</p>
                    <p>Si vous n'avez pas créé de compte, vous pouvez ignorer cet email.</p>
                    <br>
                    <p>Cordialement,<br>L'équipe ECommerce Auth</p>
                ";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'envoi de l'email de confirmation à {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendPasswordResetAsync(string email, string userName, string resetLink)
        {
            try
            {
                var subject = "Réinitialisation de votre mot de passe";
                var body = $@"
                    <h2>Réinitialisation de mot de passe</h2>
                    <p>Bonjour {userName},</p>
                    <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
                    <p>Cliquez sur le lien ci-dessous pour créer un nouveau mot de passe :</p>
                    <p><a href='{resetLink}' style='background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>Réinitialiser mon mot de passe</a></p>
                    <p>Ce lien expirera dans 24 heures.</p>
                    <p>Si vous n'avez pas demandé cette réinitialisation, vous pouvez ignorer cet email en toute sécurité.</p>
                    <br>
                    <p>Cordialement,<br>L'équipe ECommerce Auth</p>
                ";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'envoi de l'email de réinitialisation à {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendTwoFactorCodeAsync(string email, string userName, string code)
        {
            try
            {
                var subject = "Votre code d'authentification à deux facteurs";
                var body = $@"
                    <h2>Code d'authentification</h2>
                    <p>Bonjour {userName},</p>
                    <p>Voici votre code d'authentification à deux facteurs :</p>
                    <h1 style='text-align: center; color: #007bff; font-size: 2em; letter-spacing: 5px;'>{code}</h1>
                    <p>Ce code expire dans 5 minutes.</p>
                    <p>Si vous n'avez pas demandé ce code, veuillez sécuriser votre compte immédiatement.</p>
                    <br>
                    <p>Cordialement,<br>L'équipe ECommerce Auth</p>
                ";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'envoi du code 2FA à {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendWelcomeEmailAsync(string email, string userName)
        {
            try
            {
                var subject = "Bienvenue sur notre plateforme!";
                var body = $@"
                    <h2>Bienvenue {userName}!</h2>
                    <p>Votre compte a été confirmé avec succès.</p>
                    <p>Vous pouvez maintenant profiter de toutes les fonctionnalités de notre plateforme e-commerce :</p>
                    <ul>
                        <li>Parcourir et acheter des produits</li>
                        <li>Gérer votre profil et vos commandes</li>
                        <li>Bénéficier d'offres exclusives</li>
                    </ul>
                    <p>N'hésitez pas à nous contacter si vous avez des questions.</p>
                    <br>
                    <p>Cordialement,<br>L'équipe ECommerce Auth</p>
                ";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'envoi de l'email de bienvenue à {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendAccountLockedNotificationAsync(string email, string userName, string reason, DateTime lockoutEnd)
        {
            try
            {
                var subject = "Compte verrouillé - Action de sécurité";
                var body = $@"
                    <h2>Compte temporairement verrouillé</h2>
                    <p>Bonjour {userName},</p>
                    <p>Votre compte a été temporairement verrouillé pour des raisons de sécurité.</p>
                    <p><strong>Raison :</strong> {reason}</p>
                    <p><strong>Fin du verrouillage :</strong> {lockoutEnd:yyyy-MM-dd HH:mm} UTC</p>
                    <p>Si vous pensez que c'est une erreur ou si votre compte a été compromis, contactez notre support immédiatement.</p>
                    <br>
                    <p>Cordialement,<br>L'équipe ECommerce Auth</p>
                ";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'envoi de la notification de verrouillage à {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendPasswordChangedNotificationAsync(string email, string userName, string ipAddress)
        {
            try
            {
                var subject = "Mot de passe modifié";
                var body = $@"
                    <h2>Mot de passe modifié</h2>
                    <p>Bonjour {userName},</p>
                    <p>Votre mot de passe a été modifié avec succès.</p>
                    <p><strong>Adresse IP :</strong> {ipAddress}</p>
                    <p><strong>Date :</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC</p>
                    <p>Si vous n'avez pas effectué cette modification, contactez notre support immédiatement.</p>
                    <br>
                    <p>Cordialement,<br>L'équipe ECommerce Auth</p>
                ";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'envoi de la notification de changement de mot de passe à {Email}", email);
                return false;
            }
        }

        public async Task<bool> SendSuspiciousLoginAttemptAsync(string email, string userName, string ipAddress, string userAgent)
        {
            try
            {
                var subject = "Tentative de connexion suspecte détectée";
                var body = $@"
                    <h2>Activité suspecte détectée</h2>
                    <p>Bonjour {userName},</p>
                    <p>Nous avons détecté une tentative de connexion suspecte sur votre compte.</p>
                    <p><strong>Adresse IP :</strong> {ipAddress}</p>
                    <p><strong>Navigateur :</strong> {userAgent}</p>
                    <p><strong>Date :</strong> {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC</p>
                    <p>Si c'était vous, vous pouvez ignorer cet email. Sinon, nous vous recommandons de :</p>
                    <ul>
                        <li>Changer votre mot de passe immédiatement</li>
                        <li>Activer l'authentification à deux facteurs</li>
                        <li>Vérifier vos sessions actives</li>
                    </ul>
                    <br>
                    <p>Cordialement,<br>L'équipe ECommerce Auth</p>
                ";

                return await SendEmailAsync(email, subject, body);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'envoi de l'alerte de tentative suspecte à {Email}", email);
                return false;
            }
        }

        private async Task<bool> SendEmailAsync(string toEmail, string subject, string body)
        {
            try
            {
                // Skip sending if credentials are not configured
                if (string.IsNullOrEmpty(_smtpUsername) || string.IsNullOrEmpty(_smtpPassword))
                {
                    _logger.LogWarning("Configuration SMTP manquante. Email non envoyé à {Email}", toEmail);
                    return false;
                }

                using var client = new SmtpClient(_smtpHost, _smtpPort);
                client.EnableSsl = _enableSsl;
                client.UseDefaultCredentials = false;
                client.Credentials = new NetworkCredential(_smtpUsername, _smtpPassword);

                var message = new MailMessage
                {
                    From = new MailAddress(_fromEmail, _fromName),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };

                message.To.Add(toEmail);

                await client.SendMailAsync(message);

                _logger.LogInformation("Email envoyé avec succès à {Email}", toEmail);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erreur lors de l'envoi d'email à {Email}", toEmail);
                return false;
            }
        }
    }
}