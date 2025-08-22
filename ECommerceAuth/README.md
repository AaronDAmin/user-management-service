# 🚀 ECommerce Auth API - Système d'Authentification Sécurisé

## 📋 Description

API d'authentification complète et sécurisée pour plateforme e-commerce construite avec **ASP.NET Core 9** et **Clean Architecture**. 

### ✨ Fonctionnalités Principales

- 🔐 **Authentification JWT sécurisée** avec refresh tokens
- 👥 **Gestion des rôles** (Buyer, Seller, Admin)
- 📧 **Confirmation d'email** obligatoire
- 🔑 **Authentification 2FA** (TOTP/Google Authenticator)
- 🛡️ **Protection anti-brute force** avec verrouillage de compte
- 🔄 **Réinitialisation de mot de passe** sécurisée
- 📊 **Audit des connexions** avec IP et User-Agent
- 🏗️ **Architecture Clean** (Domain, Application, Infrastructure, API)
- 🔒 **Sécurité renforcée** (HTTPS, CORS, XSS, CSRF)

## 🏗️ Architecture

```
ECommerceAuth/
├── src/
│   ├── ECommerceAuth.Domain/          # Entités et logique métier
│   │   ├── Entities/                  # User, Role, RefreshToken, LoginHistory
│   │   └── Enums/                     # UserRole
│   ├── ECommerceAuth.Application/     # Services et interfaces
│   │   ├── DTOs/                      # Data Transfer Objects
│   │   └── Interfaces/                # IAuthService, ITokenService, IEmailService
│   ├── ECommerceAuth.Infrastructure/  # Accès aux données et services externes
│   │   ├── Data/                      # DbContext et configurations EF Core
│   │   └── Services/                  # Implémentations des services
│   └── ECommerceAuth.API/             # Contrôleurs et configuration
│       └── Controllers/               # AuthController
└── ECommerceAuth.sln                  # Solution
```

## 🛠️ Technologies Utilisées

- **Framework** : ASP.NET Core 9.0
- **Base de données** : SQL Server / PostgreSQL
- **ORM** : Entity Framework Core 9.0
- **Authentification** : JWT Bearer Tokens
- **Validation** : FluentValidation
- **Documentation** : Swagger/OpenAPI
- **2FA** : OTP.NET (TOTP)
- **Hashage** : BCrypt.Net
- **QR Codes** : QRCoder

## 📦 Installation et Configuration

### 1. Prérequis

- **.NET 9 SDK** : [Télécharger](https://dotnet.microsoft.com/download/dotnet/9.0)
- **SQL Server** ou **PostgreSQL**
- **Visual Studio 2022** ou **VS Code** (optionnel)

### 2. Cloner et Restaurer

```bash
git clone <votre-repo>
cd ECommerceAuth
dotnet restore
```

### 3. Configuration de la Base de Données

#### Option A : SQL Server (Recommandé)
```json
// appsettings.json
"ConnectionStrings": {
  "DefaultConnection": "Server=localhost;Database=ECommerceAuthDb;Trusted_Connection=true;TrustServerCertificate=true;"
}
```

#### Option B : PostgreSQL
```json
// appsettings.json
"ConnectionStrings": {
  "DefaultConnection": "Host=localhost;Database=ECommerceAuthDb;Username=postgres;Password=votre_mot_de_passe;"
}
```

Puis modifiez `Program.cs` :
```csharp
// Remplacer UseSqlServer par UseNpgsql
options.UseNpgsql(connectionString);
```

### 4. Configuration JWT et Email

Modifiez `appsettings.json` :

```json
{
  "Jwt": {
    "Secret": "CHANGEZ_CETTE_CLE_SECRETE_TRES_LONGUE_ET_SECURISEE_123456789",
    "Issuer": "ECommerceAuth",
    "Audience": "ECommerceAuth",
    "AccessTokenExpirationMinutes": 30,
    "RefreshTokenExpirationDays": 7,
    "RefreshTokenExpirationDaysRememberMe": 30
  },
  "Email": {
    "SmtpHost": "smtp.gmail.com",
    "SmtpPort": 587,
    "SmtpUsername": "votre_email@gmail.com",
    "SmtpPassword": "votre_mot_de_passe_app",
    "FromEmail": "noreply@votredomaine.com",
    "FromName": "ECommerce Auth",
    "EnableSsl": true
  }
}
```

### 5. Lancer l'Application

```bash
cd src/ECommerceAuth.API
dotnet run
```

L'API sera disponible sur :
- **HTTPS** : https://localhost:7000
- **HTTP** : http://localhost:5000
- **Swagger** : https://localhost:7000 (racine)

## 📚 Utilisation de l'API

### 🔐 Endpoints Principaux

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/auth/register` | POST | Inscription d'un nouvel utilisateur |
| `/api/auth/login` | POST | Connexion avec email/mot de passe |
| `/api/auth/refresh-token` | POST | Rafraîchir le token d'accès |
| `/api/auth/logout` | POST | Déconnexion et révocation des tokens |
| `/api/auth/confirm-email` | GET | Confirmation d'email |
| `/api/auth/forgot-password` | POST | Demande de réinitialisation |
| `/api/auth/reset-password` | POST | Réinitialisation du mot de passe |
| `/api/auth/enable-2fa` | POST | Activer l'authentification 2FA |
| `/api/auth/disable-2fa` | POST | Désactiver l'authentification 2FA |

### 📝 Exemples d'Utilisation

#### 1. Inscription
```json
POST /api/auth/register
{
  "userName": "johndoe",
  "email": "john@example.com",
  "password": "MonMotDePasse123!",
  "confirmPassword": "MonMotDePasse123!",
  "firstName": "John",
  "lastName": "Doe",
  "role": "Buyer",
  "acceptTerms": true
}
```

#### 2. Connexion
```json
POST /api/auth/login
{
  "email": "john@example.com",
  "password": "MonMotDePasse123!",
  "rememberMe": true
}
```

**Réponse :**
```json
{
  "success": true,
  "message": "Connexion réussie",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "base64-encoded-refresh-token",
    "tokenType": "Bearer",
    "expiresIn": 1800,
    "user": {
      "id": "guid",
      "userName": "johndoe",
      "email": "john@example.com",
      "emailConfirmed": true
    },
    "roles": ["Buyer"]
  }
}
```

#### 3. Utilisation avec Authorization Header
```http
GET /api/protected-endpoint
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## 🔒 Sécurité

### Bonnes Pratiques Implémentées

1. **JWT Sécurisé** :
   - Clé secrète de 256 bits minimum
   - Durée de vie courte (30 min)
   - Signature HMAC SHA-256

2. **Refresh Tokens** :
   - Stockage sécurisé en base
   - Révocation possible
   - Rotation automatique

3. **Mots de Passe** :
   - Hashage BCrypt avec salt
   - Politique de complexité
   - Jamais stockés en clair

4. **Protection Anti-Brute Force** :
   - Limitation des tentatives (5 max)
   - Verrouillage temporaire (15 min)
   - Audit des tentatives

5. **2FA** :
   - TOTP compatible Google Authenticator
   - QR Code pour configuration
   - Codes de backup (à implémenter)

6. **En-têtes de Sécurité** :
   - HSTS (HTTPS forcé)
   - X-Frame-Options (anti-clickjacking)
   - X-XSS-Protection
   - Content-Security-Policy

## 🧪 Tests avec Postman

### Collection Postman

1. **Importer la collection** (créer un fichier `ECommerceAuth.postman_collection.json`)
2. **Variables d'environnement** :
   - `baseUrl`: https://localhost:7000
   - `accessToken`: (sera rempli automatiquement)

### Scénario de Test Complet

1. **Inscription** → Vérifier email de confirmation
2. **Confirmation d'email** → Activer le compte
3. **Connexion** → Récupérer les tokens
4. **Accès aux endpoints protégés** → Utiliser le token
5. **Refresh token** → Renouveler l'accès
6. **Activation 2FA** → Scanner le QR code
7. **Connexion avec 2FA** → Utiliser le code TOTP
8. **Déconnexion** → Révoquer les tokens

## 📊 Base de Données

### Schéma Principal

```sql
-- Table Users
Users (
  Id UNIQUEIDENTIFIER PRIMARY KEY,
  UserName NVARCHAR(50) UNIQUE NOT NULL,
  Email NVARCHAR(255) UNIQUE NOT NULL,
  PasswordHash NVARCHAR(255) NOT NULL,
  EmailConfirmed BIT DEFAULT 0,
  TwoFactorEnabled BIT DEFAULT 0,
  FailedLoginAttempts INT DEFAULT 0,
  LockoutEnd DATETIME2 NULL,
  CreatedAt DATETIME2 NOT NULL,
  -- ... autres colonnes
)

-- Table Roles
Roles (
  Id UNIQUEIDENTIFIER PRIMARY KEY,
  Name NVARCHAR(50) NOT NULL,
  Description NVARCHAR(500),
  CreatedAt DATETIME2 NOT NULL
)

-- Table UserRoles (Many-to-Many)
UserRoles (
  Id UNIQUEIDENTIFIER PRIMARY KEY,
  UserId UNIQUEIDENTIFIER FOREIGN KEY REFERENCES Users(Id),
  RoleId UNIQUEIDENTIFIER FOREIGN KEY REFERENCES Roles(Id),
  AssignedAt DATETIME2 NOT NULL
)
```

### Données de Seed

Les rôles par défaut sont créés automatiquement :
- **Buyer** : Utilisateur standard
- **Seller** : Peut vendre (hérite de Buyer)
- **Admin** : Droits complets

## 🚀 Déploiement

### Production

1. **Variables d'environnement** :
```bash
export ASPNETCORE_ENVIRONMENT=Production
export JWT_SECRET="votre-cle-secrete-production"
export CONNECTION_STRING="votre-chaine-connexion-production"
```

2. **Migration de la base** :
```bash
dotnet ef database update --project src/ECommerceAuth.Infrastructure
```

3. **Build et publication** :
```bash
dotnet publish -c Release -o ./publish
```

### Docker (Optionnel)

```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore
RUN dotnet publish -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "ECommerceAuth.API.dll"]
```

## 🔧 Personnalisation

### Ajouter de Nouveaux Rôles

1. Modifier l'enum `UserRole` dans le Domain
2. Mettre à jour les données de seed
3. Créer une migration

### Étendre les Entités

1. Ajouter propriétés dans les entités du Domain
2. Configurer dans les `EntityConfiguration`
3. Créer et appliquer une migration

### Ajouter des Endpoints

1. Créer les DTOs dans Application
2. Étendre les interfaces de service
3. Implémenter dans Infrastructure
4. Ajouter les endpoints dans les contrôleurs

## 🐛 Dépannage

### Problèmes Courants

1. **Erreur de connexion DB** :
   - Vérifier la chaîne de connexion
   - S'assurer que SQL Server est démarré
   - Vérifier les permissions

2. **JWT invalide** :
   - Vérifier la clé secrète (32+ caractères)
   - Contrôler l'expiration du token
   - Vérifier l'en-tête Authorization

3. **Emails non envoyés** :
   - Configurer SMTP correctement
   - Utiliser un mot de passe d'application pour Gmail
   - Vérifier les logs d'erreurs

### Logs et Monitoring

Les logs sont configurés pour :
- Console (développement)
- Fichiers (production recommandée)
- Application Insights (Azure)

## 📞 Support

Pour toute question ou problème :
- 📧 Email : support@ecommerceauth.com
- 📝 Issues : GitHub Issues
- 📖 Documentation : Swagger UI

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

---

**🎉 Votre API d'authentification sécurisée est prête !**

N'oubliez pas de :
- [ ] Changer la clé JWT secrète
- [ ] Configurer l'envoi d'emails
- [ ] Tester tous les endpoints
- [ ] Sécuriser la base de données
- [ ] Configurer HTTPS en production