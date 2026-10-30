<?php
/**
 * Client-name guard for fixtures and release files. The names are held as
 * SHA-1 hashes of their lower-case letters and digits, so the guard itself
 * names no client. Text is split into words, and every run of one to three
 * words is compacted and hashed ("Firm & Name" and "Firm and Name" both
 * match). Add a name by hashing its compact form.
 *
 * @package MLT\SchemaAudit
 */

// phpcs:disable

const MLTSA_CLIENT_NAME_HASHES = array( '52db9057163f2b831a5452d895239a249597d1cc', '2f72c3e6dc530e3febb0f9a0bc736f4f78df8523', 'aa1e46ccd3f037a80a4739436df838df54b066a8', 'd5cd0dfdb98b20bd4e0e260a249098a574c581a8', '90a0e545bb4def2d83d7e1faf78b8ad1a61bfc77', 'b4f2365b1ba376ad2293feb1959dd0d609bca878', '351f0b0d14fccd417255f79c200f3322ea1f7fd6', '5d74ae093a16a00e5af127763f2dc7e13988f162', 'b07318fcab9d6a233ec421410823dca70bbf4dda', '4c912ad3686ed4d1fb9eef3899d98f01bd8a6606', '96417ec9fcb71f3ce4d6d67834a083e6e74ff436', '9ccc3e27e86b7593fde9787a0370a97463c8dba5', '1da3ad4a728f1f4add7494ebe5bd7a3d5c20c455', '27386ceaaece3b34ffa6c5e67c7f81114b80214d', '1e6cf73fcf62ec219cf9258f3e38bd124402e984', 'a1959bced6c033227309df87d1b3fcc0e918dbd9',  );

/**
 * The first word run in a text that matches a client-name hash, or ''.
 *
 * @param string $text Text.
 * @return string
 */
function mltsa_client_name_hit( $text ) {
	$words = preg_split( '/[^a-z0-9]+/', strtolower( (string) $text ), -1, PREG_SPLIT_NO_EMPTY );
	$set   = array_flip( MLTSA_CLIENT_NAME_HASHES );
	$count = count( $words );
	for ( $i = 0; $i < $count; $i++ ) {
		$gram = '';
		for ( $n = 0; $n < 3 && $i + $n < $count; $n++ ) {
			$gram .= $words[ $i + $n ];
			if ( isset( $set[ sha1( $gram ) ] ) ) {
				return implode( ' ', array_slice( $words, $i, $n + 1 ) );
			}
		}
	}
	return '';
}
