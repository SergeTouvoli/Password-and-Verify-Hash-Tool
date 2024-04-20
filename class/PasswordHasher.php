<?php
class PasswordHasher {

    /**
     * Génère un hachage bcrypt pour le texte donné.
     *
     * @param string $text Le texte à hacher.
     * @return string Le hachage bcrypt résultant.
    */
    public static function hashBcrypt($text) {
        return password_hash($text, PASSWORD_BCRYPT);
    }
    
    /**
     * Génère un hachage MD5 pour le texte donné.
     *
     * @param string $text Le texte à hacher.
     * @return string Le hachage MD5 résultant.
    */
    public static function hashMd5($text) {
        return md5($text);
    }
    

    /**
     * Génère un hachage pour le texte donné en utilisant l'algorithme spécifié.
     *
     * @param string $text Le texte à hacher.
     * @param string $hashType Le type de hachage à utiliser (ex: "sha1", "sha256", "sha512").
     * @return string Le hachage résultant.
    */
    public static function hashSha(string $text,string $hashType): string {
        return hash($hashType, $text);
    }



    /**
     * Génère un hachage Argon2 pour le texte donné.
     *
     * @param string $text Le texte à hacher.
     * @return string Le hachage Argon2 résultant.
    */
    public static function hashArgon2($text) {
        $options = [
            'memory_cost' => 1<<16, // 64MB
            'time_cost'   => 4,
            'threads'     => 2,
        ];

        return password_hash($text, PASSWORD_ARGON2ID, $options);
    }


    /**
     * Détermine le type de hachage d'un hash donné.
     *
     * @param string $hash Le hash dont le type doit être déterminé.
     * @return string Le type de hachage, ou une chaîne vide si le type de hachage n'est pas reconnu.
    */
    public static function detectHashType(string $hash) {
       
        if(self::isInBcrypt($hash)){
            return 'bcrypt';
        }

        if(self::isInMd5($hash)){
            return 'md5';
        }

        if(self::isInSha1($hash)){
            return 'sha1';
        }

        if(self::isInSha256($hash)){
            return 'sha256';
        }

        if(self::isInSha512($hash)){
            return 'sha512';
        }

        if(self::isInArgon2($hash)){
            return 'argon2';
        }

        return '';
    }


    /**
     * Vérifie si le hachage donné est de type bcrypt.
     *
     * @param string $hash Le hachage à vérifier.
     * @return bool Retourne true si le hachage est de type bcrypt, sinon false.
    */
    private static function isInBcrypt(string $hash) {
        $info = password_get_info($hash);
    
        if ($info['algoName'] === 'bcrypt') {
            return true;
        }
    
        return false;
    }


    /**
     * Vérifie si le hachage donné est de type MD5.
     *
     * @param string $hash Le hachage à vérifier.
     * @return bool Retourne true si le hachage est de type MD5, sinon false.
    */
    private static function isInMd5(string $hash) {
        if (strlen($hash) === 32) {
            if (preg_match('/^[a-f0-9]{32}$/', $hash)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Vérifie si le hachage donné est de type SHA1.
     *
     * @param string $hash Le hachage à vérifier.
     * @return bool Retourne true si le hachage est de type SHA1, sinon false.
    */
    private static function isInSha1(string $hash) {
        if (strlen($hash) === 40) {
            if (preg_match('/^[a-f0-9]{40}$/', $hash)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Vérifie si le hachage donné est de type SHA256.
     *
     * @param string $hash Le hachage à vérifier.
     * @return bool Retourne true si le hachage est de type SHA256, sinon false.
    */
    private static function isInSha256(string $hash) {
        if (strlen($hash) === 64) {
            if (preg_match('/^[a-f0-9]{64}$/', $hash)) {
                return true;
            }
        }

        return false;
    }


    /**
     * Vérifie si le hachage donné est de type SHA512.
     *
     * @param string $hash Le hachage à vérifier.
     * @return bool Retourne true si le hachage est de type SHA512, sinon false.
    */
    private static function isInSha512(string $hash): bool {
        if (strlen($hash) === 128) {
            if (preg_match('/^[a-f0-9]{128}$/', $hash)) {
                return true;
            }
        }
        return false;
    }
    
    

    /**
     * Vérifie si le hachage donné est de type Argon2.
     *
     * @param string $hash Le hachage à vérifier.
     * @return bool Retourne true si le hachage est de type Argon2, sinon false.
    */
    private static function isInArgon2(string $hash): bool {
        $info = password_get_info($hash);
    
        if (isset($info['algoName']) && $info['algoName'] === 'argon2id') {
            return true;
        }
    
        return false;
    }
    
    

    /**
     * Vérifie si le hachage donné correspond au texte donné en utilisant le type de hachage spécifié.
     *
     * @param string $hashType Le type de hachage à utiliser (ex: "md5", "sha1", "bcrypt", "argon2").
     * @param string $hash Le hachage à vérifier.
     * @param string $text Le texte à vérifier.
     * @return bool Retourne true si le hachage correspond au texte, sinon false.
    */
    public static function verifyHash(string $hashType, string $hash, string $text):bool {
        switch ($hashType) {
            case 'md5':
                return self::verifyMd5($hash, $text);
            case 'sha256':
            case 'sha512':
            case 'sha1':
                return self::verifySha($hash, $text, $hashType);
            case 'bcrypt':
            case 'argon2':
                return self::verifyBcryptOrArgon2($hash, $text);
            default:
                return false; 
        }
    }


    /**
     * Vérifie si le hachage SHA donné correspond au texte donné.
     *
     * @param string $hash Le hachage à vérifier.
     * @param string $text Le texte à vérifier.
     * @param string $hashType Le type de hachage (SHA) utilisé( sha1,sha256 ou sha512)
     * @return bool Retourne true si le hachage correspond au texte, sinon false.
    */
    private static function verifySha(string $hash,string $text,string $hashType): bool{
        if(hash($hashType, $text) == $hash){
            return true;
        }
        return false;
    }


    /**
     * Vérifie si le hachage bcrypt ou argon2 donné correspond au texte donné.
     *
     * @param string $hash Le hachage bcrypt ou argon2 à vérifier.
     * @param string $text Le texte à vérifier.
     * @return bool Retourne true si le hachage correspond au texte, sinon false.
    */
    private static function verifyBcryptOrArgon2(string $hash, string $text): bool {
        return password_verify($text, $hash);
    }


    /**
     * Vérifie si le hachage MD5 donné correspond au texte donné.
     *
     * @param string $hash Le hachage MD5 à vérifier.
     * @param string $text Le texte à vérifier.
     * @return bool Retourne true si le hachage correspond au texte, sinon false.
    */
    private static function verifyMd5(string $hash, string $text): bool{

        if(md5($text) == $hash){
            return true;
        }

        return false;
    }

    
}
?>
