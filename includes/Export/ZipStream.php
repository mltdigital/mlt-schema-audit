<?php
/**
 * A minimal ZIP writer that builds the archive in memory and streams it,
 * so an export never writes a file to disk (contract section 7, E2).
 * ZipArchive needs a file path, which is why it is not used. Entries are
 * deflated; names are UTF-8. Pure PHP, so it is unit tested.
 *
 * @package MLT\SchemaAudit
 */

namespace MLT\SchemaAudit\Export;

defined( 'ABSPATH' ) || defined( 'MLTSA_TESTING' ) || exit;

/**
 * ZipStream.
 */
class ZipStream {

	/**
	 * Central directory records.
	 *
	 * @var array
	 */
	private $central = array();

	/**
	 * Bytes written so far.
	 *
	 * @var int
	 */
	private $offset = 0;

	/**
	 * Output callable (receives a string).
	 *
	 * @var callable
	 */
	private $out;

	/**
	 * DOS time and date of the export.
	 *
	 * @var array
	 */
	private $dos;

	/**
	 * Constructor.
	 *
	 * @param callable $out  Receives each chunk.
	 * @param int      $time Timestamp for entry dates.
	 */
	public function __construct( callable $out, $time ) {
		$this->out = $out;
		$t         = getdate( (int) $time );
		$this->dos = array(
			( $t['hours'] << 11 ) | ( $t['minutes'] << 5 ) | (int) ( $t['seconds'] / 2 ),
			( max( 0, $t['year'] - 1980 ) << 9 ) | ( $t['mon'] << 5 ) | $t['mday'],
		);
	}

	/**
	 * Add a file.
	 *
	 * @param string $name Name inside the archive.
	 * @param string $data Contents.
	 */
	public function add( $name, $data ) {
		$name       = (string) $name;
		$data       = (string) $data;
		$crc        = crc32( $data );
		$compressed = gzdeflate( $data, 6 );
		$method     = 8;
		if ( false === $compressed ) {
			$compressed = $data;
			$method     = 0;
		}
		$flags  = 0x0800; // UTF-8 names.
		$header = pack( 'VvvvvvVVVvv', 0x04034b50, 20, $flags, $method, $this->dos[0], $this->dos[1], $crc, strlen( $compressed ), strlen( $data ), strlen( $name ), 0 ) . $name;
		$this->emit( $header . $compressed );
		$this->central[] = pack( 'VvvvvvvVVVvvvvvVV', 0x02014b50, 20, 20, $flags, $method, $this->dos[0], $this->dos[1], $crc, strlen( $compressed ), strlen( $data ), strlen( $name ), 0, 0, 0, 0, 0, $this->offset - strlen( $header . $compressed ) ) . $name;
	}

	/**
	 * Write the central directory and end record.
	 */
	public function finish() {
		$start = $this->offset;
		$dir   = implode( '', $this->central );
		$this->emit( $dir );
		$this->emit( pack( 'VvvvvVVv', 0x06054b50, 0, 0, count( $this->central ), count( $this->central ), strlen( $dir ), $start, 0 ) );
	}

	/**
	 * Send bytes to the output.
	 *
	 * @param string $bytes Bytes.
	 */
	private function emit( $bytes ) {
		$this->offset += strlen( $bytes );
		call_user_func( $this->out, $bytes );
	}
}
