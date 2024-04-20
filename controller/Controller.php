<?php
require_once dirname(__DIR__).'/autoload.php';

class Controller extends AbstractController {

    private $directory;

    public function __construct(){
        $this->directory = "home";
    }

    public function getHomePage(){
        $pageTitle = "Page d'accueil";
        $pageDescription = "";

        $this->renderView($this->directory,"home", [
            "pageTitle" => $pageTitle,
            "pageDescription" => $pageDescription,
        ]);

    }

    public function verifHash(){

        $response = [];
        $response['success'] = false;
        $response['msg'] = "";

        $data = [];
        $data['plain_text'] = ValidatorTools::sanitizePostParam('plain_text');
        $data['hash'] = ValidatorTools::sanitizePostParam('hash');

        //$response['info'] = password_get_info($data['hash']);

        $data['hash_type'] = PasswordHasher::detectHashType($data['hash']);

        if($data['hash_type'] == ''){
            $response['msg'] = "Type de hash inconnu"; 
            echo json_encode($response);
            return;    
        }    

        if(PasswordHasher::verifyHash($data['hash_type'],$data['hash'],$data['plain_text'])){
            $response['success'] = true;
            $response['msg'] = "Le hash (" . $data['hash_type'] . ") correspond au texte saisi";
        } else {
            $response['msg'] = "Le hash (" . $data['hash_type'] . ") ne correspond pas au texte saisie";
        }

        echo json_encode($response);    
    }

    public function hashText(){

        $response = [];

        $response['success'] = false;
        $response['error'] = "";
        $response['result'] = "";

        $data = [];
        $data['hash_text'] = ValidatorTools::sanitizePostParam('hash_text');
        $data['hash_type'] = ValidatorTools::sanitizePostParam('hash_type');
        

        if(empty($data['hash_type']) || !in_array($data['hash_type'],HASH_TYPES)){
            $response['error'] = "Veuillez sélectionner un type de hash";
            echo json_encode($response);
            return;
        }

        if(empty($data['hash_text'])){
            $response['error'] = "Veuillez saisir un texte à hasher";
            echo json_encode($response);
            return;
        }

        if($data['hash_type'] == "bcrypt"){
            $response['success'] = true;
            $response['result'] = PasswordHasher::hashBcrypt($data['hash_text']);
            echo json_encode($response);
            return;
        }

        if($data['hash_type'] == "md5"){
            $response['success'] = true;
            $response['result'] = PasswordHasher::hashMd5($data['hash_text']);
            echo json_encode($response);
            return;
        }

        if($data['hash_type'] == "sha1" ||  $data['hash_type'] == "sha256" || $data['hash_type'] == "sha512" ){
            $response['success'] = true;
            $response['result'] = PasswordHasher::hashSha($data['hash_text'],$data['hash_type']);
            echo json_encode($response);
            return;
        }

        if($data['hash_type'] == "argon2"){
            $response['success'] = true;
            $response['result'] = PasswordHasher::hashArgon2($data['hash_text']);
            echo json_encode($response);
            return;
        }

        echo json_encode($response);
    }



}