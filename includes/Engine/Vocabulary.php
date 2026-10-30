<?php
/**
 * The slice of the schema.org type hierarchy the rules need.
 *
 * Plan correction: LegalService is a LocalBusiness subtype, so matching type
 * names exactly is not enough. Types outside this map are treated as unknown,
 * never as errors.
 *
 * Source: https://schema.org/docs/full.html (reviewed 2026-10-30).
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Engine;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * Vocabulary.
 */
class Vocabulary {

	/**
	 * Type => direct parents.
	 *
	 * @var array
	 */
	const PARENTS = array(
		'Thing'                    => array(),
		'Organization'             => array( 'Thing' ),
		'Corporation'              => array( 'Organization' ),
		'NGO'                      => array( 'Organization' ),
		'Place'                    => array( 'Thing' ),
		'AdministrativeArea'       => array( 'Place' ),
		'City'                     => array( 'AdministrativeArea' ),
		'Country'                  => array( 'AdministrativeArea' ),
		'State'                    => array( 'AdministrativeArea' ),
		'GovernmentOrganization'   => array( 'Organization' ),
		'Product'                  => array( 'Thing' ),
		'PropertyValue'            => array( 'StructuredValue' ),
		'OfferCatalog'             => array( 'ItemList' ),
		'Action'                   => array( 'Thing' ),
		'LocalBusiness'            => array( 'Organization', 'Place' ),
		'LegalService'             => array( 'LocalBusiness' ),
		'Attorney'                 => array( 'LegalService' ),
		'Notary'                   => array( 'LegalService' ),
		'ProfessionalService'      => array( 'LocalBusiness' ),
		'FinancialService'         => array( 'LocalBusiness' ),
		'AccountingService'        => array( 'FinancialService' ),
		'RealEstateAgent'          => array( 'LocalBusiness' ),
		'Person'                   => array( 'Thing' ),
		'Intangible'               => array( 'Thing' ),
		'StructuredValue'          => array( 'Intangible' ),
		'ContactPoint'             => array( 'StructuredValue' ),
		'PostalAddress'            => array( 'ContactPoint' ),
		'GeoCoordinates'           => array( 'StructuredValue' ),
		'OpeningHoursSpecification' => array( 'StructuredValue' ),
		'Service'                  => array( 'Intangible' ),
		'Offer'                    => array( 'Intangible' ),
		'ItemList'                 => array( 'Intangible' ),
		'BreadcrumbList'           => array( 'ItemList' ),
		'ListItem'                 => array( 'Intangible' ),
		'Rating'                   => array( 'Intangible' ),
		'AggregateRating'          => array( 'Rating' ),
		'CreativeWork'             => array( 'Thing' ),
		'WebSite'                  => array( 'CreativeWork' ),
		'WebPage'                  => array( 'CreativeWork' ),
		'AboutPage'                => array( 'WebPage' ),
		'ContactPage'              => array( 'WebPage' ),
		'FAQPage'                  => array( 'WebPage' ),
		'ProfilePage'              => array( 'WebPage' ),
		'CollectionPage'           => array( 'WebPage' ),
		'ItemPage'                 => array( 'WebPage' ),
		'SearchResultsPage'        => array( 'WebPage' ),
		'Article'                  => array( 'CreativeWork' ),
		'NewsArticle'              => array( 'Article' ),
		'BlogPosting'              => array( 'Article' ),
		'Review'                   => array( 'CreativeWork' ),
		'MediaObject'              => array( 'CreativeWork' ),
		'ImageObject'              => array( 'MediaObject' ),
		'Comment'                  => array( 'CreativeWork' ),
		'Question'                 => array( 'Comment' ),
		'Answer'                   => array( 'Comment' ),
	);

	/**
	 * Whether any of the given types is the target type or a subtype of it.
	 *
	 * @param array  $types  Types.
	 * @param string $target Target type.
	 * @return bool
	 */
	public static function is_a( array $types, $target ) {
		foreach ( $types as $type ) {
			if ( self::type_is_a( (string) $type, (string) $target, 0 ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Recursive subtype test.
	 *
	 * @param string $type   Type.
	 * @param string $target Target.
	 * @param int    $depth  Guard.
	 * @return bool
	 */
	private static function type_is_a( $type, $target, $depth ) {
		if ( $type === $target ) {
			return true;
		}
		if ( $depth > 10 || ! isset( self::PARENTS[ $type ] ) ) {
			return false;
		}
		foreach ( self::PARENTS[ $type ] as $parent ) {
			if ( self::type_is_a( $parent, $target, $depth + 1 ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a node describes a business (Organization or any subtype).
	 *
	 * @param array $types Types.
	 * @return bool
	 */
	public static function is_business( array $types ) {
		return self::is_a( $types, 'Organization' );
	}
}
