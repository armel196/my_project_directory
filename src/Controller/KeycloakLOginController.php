<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Exception;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use  Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\AccessMap;

// use Nowakowskir\JWT\JWT;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class KeycloakLOginController extends AbstractController
{
    private $provider;




    public function __construct(private UserRepository $UsersRepository, private EntityManagerInterface $em)
    {
        // $this->decoded = new TokenDecoded(['payload_key' => 'value'], ['header_key' => 'value']);
        $key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqX6Vah/jb8aUe/VTaY0UrIDvScWjKF20bs/Bh2HSS/PLgjDWufzWaPDr49N7AkxlB/fNPbxwhK75f42z1bQQwgag5/+SuRV6GKxrKsfB+GfWOLyzaRecpLHT7DK6QdBdqG8vwCP+C+Kp6pnzKSRbAvobfpTwniUrhES04awWf6Ktwsttqj4NZNYnLNoIXgsdm0qFJgkqCLgqzfgB6gfpw1qE4OZAAvkAWyBCJnBKdxHHMxDyWJ86AD3FzXuoTS9y/gCDfimXhl5WoODnmfNBWdMDFltXy55sSiR0ZjklIzyeFDnqQztFs9R7mbV7BZb/9yOCHt+Az0Qyd/WMIcmciQIDAQAB";

        $this->provider = new Keycloak([
            'authServerUrl'         => 'http://localhost:8080',
            'realm'                 =>  'dev',
            'clientId'              => $_ENV['KEYCLOAK_CLIENDID'],
            'clientSecret'          => $_ENV['KEYCLOAK_CLIENTSECRET'],
            'redirectUri'           => $_ENV['KEYCLOAK_HOME'],
            'encryptionAlgorithm'   => 'RS256',                             // optional
            // 'encryptionKeyPath'     => '../key.pem',                         // optional
            'encryptionKey'         => $key,    // optional
            // 'version'               => '15.0',                            // optional


        ]);
    }

    // #[Route('/keycloak/login', name: 'app_keycloak_l_ogin')]
    // public function index(): Response
    // {
    //     return $this->render('keycloak_l_ogin/index.html.twig', [

    //     ]);
    // }

    #[Route('/login', name: 'app_keycloak_login')]
    public function keycloalLOgin(): Response
    {
        $authUrl = $this->provider->getAuthorizationUrl();

        // $_SESSION['oauth2state'] = $this->provider->getState();
        // header('Location: ' . $authUrl);
        // exit;
        // dd($authUrl);
        return $this->redirect($authUrl);
    }

    #[Route('/keycloak-callback', name: 'app_keycloak_callback')]
    public function keycloakCallback(Request $request): Response
    {

        try {
            $token = $this->provider->getAccessToken('authorization_code', [
                'code' => $request->query->get('code')
            ]);
        } catch (Exception $e) {
            exit('Failed to get access token: ' . $e->getMessage());
        }

        // Optional: Now you have a token you can look up a users profile data
        try {

            JWT::$leeway = 60; // $leeway in seconds
            $decoded = JWT::decode($token->getToken(), new Key($_ENV['KEYCLOAK_PK'], 'RS256'));

            // dd($this->UsersRepository->findByClientId($decoded->sid));
            $user = $this->UsersRepository->findByEmail($decoded->email);
            // dd($user);
            if ($user === null) {

                $user = new User();
                -$user->setEmail($decoded->email);
                $this->UsersRepository->save($user);
            }
            $user->setKeycloakId($decoded->sid);
            $user->setRoles($decoded->resource_access->{'one-portal'}->roles);
            $user->setFullName($decoded->name);
            $user->setName($decoded->preferred_username);
            $this->UsersRepository->save($user, true);

                $ok = "k";
            //                                                                                                                                                                                                                                                                                                                                                                                                                                                  
            return $this->render('keycloak_l_ogin/mapage.html.twig', [
                'ok'=>$ok
            ]);



            // $this->em->flush();
        } catch (Exception $e) {
            exit('Failed to get resource owner: ' . $e->getMessage());
        }
    }
}
