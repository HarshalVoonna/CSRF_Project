<?php
class NoCSRF
{

    public function check( $key )
    {
        if ( !isset( $_SESSION[ 'csrf_' . $key ] ) )
            return 'No CSRF session token. Ignore the form';
            
        if ( !isset( $_POST[ $key ] ) )
            return 'No CSRF form token. Ignore the form';
            
        $hash = $_SESSION[ 'csrf_' . $key ];
		
        if ( $_POST[ $key ] != $hash )
            return 'Incorrect CSRF token value. Ignore the form';
         
        return 'Not a CSRF attack. Pass the form';
    }

    public function generate( $key )
    {
        $token = time() . self::randomString( 32);
        $_SESSION[ 'csrf_' . $key ] = $token;
        return $token;
    }

    protected function randomString( $length )
    {
        $arr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijqlmnopqrtsuvwxyz0123456789';
        $max = strlen( $arr ) - 1;

        $string = '';
        for ( $i = 0; $i < $length; ++$i )
            $string .= $arr[mt_rand( 0, $max )];
        return $string;
    }
}
?>