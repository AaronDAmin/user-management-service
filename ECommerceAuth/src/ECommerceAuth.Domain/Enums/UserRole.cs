namespace ECommerceAuth.Domain.Enums
{
    /// <summary>
    /// Énumération des rôles disponibles dans la plateforme e-commerce.
    /// </summary>
    /// <remarks>
    /// Cette énumération définit les différents niveaux d'autorisation :
    /// - Buyer : Utilisateur standard qui peut acheter des produits
    /// - Seller : Utilisateur qui peut vendre des produits (hérite des droits Buyer)
    /// - Admin : Administrateur avec tous les droits de gestion
    /// 
    /// Les valeurs numériques permettent une gestion hiérarchique des permissions.
    /// </remarks>
    public enum UserRole
    {
        /// <summary>
        /// Acheteur - Peut naviguer et acheter des produits
        /// </summary>
        Buyer = 1,

        /// <summary>
        /// Vendeur - Peut vendre des produits et acheter (hérite des droits Buyer)
        /// </summary>
        Seller = 2,

        /// <summary>
        /// Administrateur - Droits complets sur la plateforme
        /// </summary>
        Admin = 3
    }
}