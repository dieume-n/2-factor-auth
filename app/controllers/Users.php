<?php

class Users extends Controller
{
    public function __construct()
    {
        $this->userModel = $this->model('User');
    }

    public function register()
    {
        // Ckeck for post request
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {

            // Sanitize post Data
            $_POST = filter_input_array(INPUT_POST, FILTER_SANITIZE_STRING);

            $data = [
                'name' => trim($_POST['name']),
                'email' => trim($_POST['email']),
                'password' => trim($_POST['password']),
                'confirmPassword' => trim($_POST['confirmPassword']),
                'token' => trim($_POST['token']),
                'name_error' => '',
                'email_error' => '',
                'password_error' => '',
                'token_error' => '',
                'confirmPassword_error' => ''
            ];

            // Validate Name
            if (empty($data['name'])) {
                $data['name_error'] = 'Please enter your Name';
            }
   
            // Validate Email
            if (empty($data['email'])) {
                $data['email_error'] = 'Please enter your email';
            } else {
                // Check email
                if ($this->userModel->findUserByEmail($data['email'])) {
                    $data['email_error'] = 'This email is already taken';
                }
            }
            // Validate Password
            if (empty($data['password'])) {
                $data['password_error'] = 'Please enter password';
            } else{
                if(!preg_match('/[A-Za-z].*[0-9]|[0-9].*[A-Za-z]/', $data['password'])){
                    $data['password_error'] = 'Password must contain both digits and letters';
                }
                if(strlen($data['password']) < 8){
                    $data['password_error'] = 'Password must be atleast 8 characters long';
                }

            }

            // Validate Token
            if (empty($data['token'])) {
                $data['token_error'] = 'No token submitted';
            }else{
                if(!Token::check($data['token'])){
                    $data['token_error'] = 'wrong token';
                }
            }

            // Validate Confirm Password
            if (empty($data['confirmPassword'])) {
                $data['confirmPassword_error'] = 'Please confirm password';
            } else {
                if ($data['password'] !== $data['confirmPassword']) {
                    $data['confirmPassword_error'] = 'Password do not match';
                }
            }
            
            // Making sure that errors are empty
            if (empty($data['name_error']) && empty($data['email_error']) && empty($data['password_error']) 
            && empty($data['confirmPassword_error']) && empty($data['token_error'])) {
                // Hashing password
                $data['password'] = password_hash($data['password'], PASSWORD_BCRYPT);

                // die(var_dump($data));
                    // Register user
                if ($this->userModel->register($data)) {
                    Session::flash('register_success', 'You are now registered and can log in');
                    redirect('users/login');
                } else {
                    die('Something went wrong');
                }

                } else {
                $this->view('users/register', $data);
            }
        } else {
            // Init Data
            $data = [
                'name' => '',
                'email' => '',
                'password' => '',
                'token' => '',
                'confirmPassword' => '',
                'name_error' => '',
                'email_error' => '',
                'token_error' => '',
                'password_error' => '',
                'confirmPassword_error' => ''
            ];

            // Load view
            $this->view('users/register', $data);
        }
    }

    public function login()
    {
        // Ckeck for post request
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {

            // Sanitize post Data
            $_POST = filter_input_array(INPUT_POST, FILTER_SANITIZE_STRING);

            $data = [
                'email' => trim($_POST['email']),
                'password' => trim($_POST['password']),
                'token' => trim($_POST['token']),
                'email_error' => '',
                'password_error' => '',
                'token_error' => ''
            ];

            // Validate Email
            if (empty($data['email'])) {
                $data['email_error'] = 'Please enter your email';
            }
            // Validate Password
            if (empty($data['password'])) {
                $data['password_error'] = 'Please enter password';
            }

            // Validate Token
            if (empty($data['token'])) {
                $data['token_error'] = 'No token submitted';
            }else{
                if(!Token::check($data['token'])){
                    $data['token_error'] = 'wrong token';
                }
            }

            // Making sure that errors are empty
            if (empty($data['email_error']) && empty($data['password_error']) && empty($data['token_error'])) {
                // Check and set logged in user
                $loggedInUser = $this->userModel->login($data['email'], $data['password']);
                if ($loggedInUser) {
                    // Session variables;
                    $this->createUserSession($loggedInUser);
                } else {
                    Session::flash('login_fail', 'Invalid email or password', 'alert alert-danger');
                    redirect('users/login');
                    exit;
                }
            } else {
                $this->view('users/login', $data);
            }
        } else {
            // Init Data
            $data = [
                'email' => '',
                'password' => '',
                'token' => '',
                'token_error' => '',
                'email_error' => '',
                'password_error' => ''
            ];
            // Load view
            $this->view('users/login', $data);
        }
    }

    public function createUserSession($user)
    {
        Session::set('user_id', $user->id);
        Session::set('user_email', $user->email);
        Session::set('user_fname', $user->firstName);
        redirect('users/auth');
    }
    public function auth()
    {
        // Ckeck for post request
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {

            // Sanitize post Data
            $_POST = filter_input_array(INPUT_POST, FILTER_SANITIZE_STRING);
            $data = [
                'secret' => trim($_POST['secret']),
                'secret_error' => '',
            ];

            // Validate Email
            if (empty($data['secret'])) {
                $data['secret_error'] = 'Please enter the verification code';
                redirect('users/auth');
            }

            // Making sure that errors are empty
            if (empty($data['secret_error']) ) {
                $authenticator = new Authenticator();
                $checkResult = $authenticator->verifyCode($_SESSION['auth_secret'], $data['secret'],0);
                if($checkResult){
                    redirect('users/portal');
                }else{
                    redirect('users/auth');
                }
            
            } else {
                $this->view('users/auth', $data);
            }
        } else {
            $data = [
                'secret' => ''
            ];
            $authenticator = new Authenticator();
            
            if(!isset($_SESSION['auth_secret'])){
                $secret = $authenticator->generateRandomSecret();
                $_SESSION['auth_secret'] = $secret;
            }
            $data['qrcode']= $authenticator->getQR('Cryptography',$_SESSION['auth_secret']);
            // Load view
            $this->view(
                'users/auth', $data);
        }
    }

    public function logout()
    {
        Session::unset('user_id');
        Session::unset('user_email');
        Session::unset('user_fname');
        Session::destroy();
        redirect('/');
    }

    public function isLoggedIn()
    {
        if (isset($_SESSION['user_id'])) {
            return true;
        } else {
            return false;
        }
    }

    public function portal()
    {
        if($this->isLoggedIn()){
            $user = $this->userModel->findUserbyID(Session::get('user_id'));

            if ($user) {
                $this->view('users/portal', $user);
            } else {
                die('sorry');
            }
        }else{
            redirect('/');
        }
       
        
    }

}
