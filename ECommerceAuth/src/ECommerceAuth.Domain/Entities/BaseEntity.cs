using System;

namespace ECommerceAuth.Domain.Entities
{
    /// <summary>
    /// Entité de base contenant les propriétés communes à toutes les entités du domaine.
    /// Cette classe implémente les bonnes pratiques de Domain-Driven Design (DDD).
    /// </summary>
    /// <remarks>
    /// - Id : Identifiant unique utilisant Guid pour éviter les collisions et améliorer la sécurité
    /// - CreatedAt : Timestamp de création pour l'audit et le suivi
    /// - UpdatedAt : Timestamp de modification pour l'audit et le suivi
    /// - IsDeleted : Soft delete pour préserver l'intégrité des données historiques
    /// </remarks>
    public abstract class BaseEntity
    {
        /// <summary>
        /// Identifiant unique de l'entité.
        /// Utilisation de Guid au lieu d'int pour éviter l'énumération et améliorer la sécurité.
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// Date et heure de création de l'entité.
        /// Utilisé pour l'audit et le suivi chronologique.
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Date et heure de la dernière modification.
        /// Null si l'entité n'a jamais été modifiée.
        /// </summary>
        public DateTime? UpdatedAt { get; set; }

        /// <summary>
        /// Indicateur de suppression logique (soft delete).
        /// Permet de "supprimer" des entités sans les effacer physiquement de la base.
        /// Utile pour l'audit, la récupération de données et l'intégrité référentielle.
        /// </summary>
        public bool IsDeleted { get; set; }

        /// <summary>
        /// Constructeur protégé pour initialiser les propriétés de base.
        /// </summary>
        protected BaseEntity()
        {
            Id = Guid.NewGuid();
            CreatedAt = DateTime.UtcNow;
            IsDeleted = false;
        }
    }
}