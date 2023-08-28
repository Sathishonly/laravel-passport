<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Auth;
use App\Models\forgotpassword;
use PHPMailer\PHPMailer\PHPMailer;

class UserController extends Controller
{

    public function register(Request $request)
    {
        $input = $request->all();
        $validation = Validator::make($input, [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
        ]);
        if ($validation->fails()) {
            return response()->json(['error' => $validation->errors(), 'status_code' => 400], 400);
        } else {

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            $token = $user->createToken('Laravel8PassportAuth')->accessToken;
            return response()->json(['status_code' => 200, 'token' => $token]);
        }
    }

    /**
     * Login Req
     */
    public function login(Request $request)
    {
        $input = $request->all();
        $validation = Validator::make($input, [
            'email' => 'required|email',
            'password' => 'required',
        ]);
        if ($validation->fails()) {
            return response()->json(['error' => $validation->errors(), 'status_code' => 400], 400);
        } else {
            $user = User::where('email', $request->email)->first();
            if ($user) {
                if (Hash::check($request->password, $user->password)) {
                    $token = $user->createToken('Laravel8PassportAuth')->accessToken;
                    return response()->json(['status_code' => 200, 'token' => $token]);
                } else {
                    return response()->json(['status_code' => 400, "error_code" => "Password mismatch"]);
                }
            } else {
                return response()->json(['status_code' => 400, 'error_code' => "User doesn't exist"]);
            }
        }
    }



    public function refreshToken(Request $request)
    {
        $user = Auth::user();
        $token = $user->createToken('Laravel8PassportAuth');
        $accessToken = $token->accessToken;

        return response()->json([
            'status_code' => 200,
            'token' => $accessToken,
        ]);
    }



    public function logout(Request $request)
    {
        $user = $request->user()->token();
        $user->revoke();
        return response()->json(['status_code' => 200, 'success' => 'You have been successfully logged out!']);
    }


    public function forgotpassword(Request $request)
    {
        require base_path("vendor/autoload.php");
        $mail = new PHPMailer(true);

        $input = $request->all();
        $validation = Validator::make($input, [
            'email' => 'required',
        ]);

        if ($validation->fails()) {
            return response()->json(['error' => $validation->errors(), 'status_code' => 400], 400);
        } else {

            $email = $request->input('email');

            $user = User::where("email", $email)->first();

            if ($user) {

                try {

                    $code = mt_rand(100000000, 999999999);
                    $link = "http://127.0.0.1:8000/resetPassword.html?id=" . $code;
                    $mail->SMTPDebug = 0;
                    $mail->isSMTP();
                    $mail->Host = 'smtp.gmail.com'; //  smtp host
                    $mail->SMTPAuth = true;


                    $mail->Username = 'example@gmail.com'; //  sender username
                    $mail->Password = '*******'; // sender password



                    $mail->SMTPSecure = 'tls'; // encryption - ssl/tls
                    $mail->Port = 587; // port - 587/465

                    $mail->setFrom('example@gmail.com', 'Forgot Password');

                    //$mail->addCC($request->emailCc);
                    //$mail->addBCC($request->emailBcc);

                    //   $mail->addReplyTo('sender-reply-email', 'sender-reply-name');

                    $mail->isHTML(true); // Set email content format to HTML

                    $mail->Subject = 'Forgot Password';
                    $mail->Body = '<html>
                <head>
                <style>
                @import url("https://fonts.googleapis.com/css2?family=Assistant:wght@300;400;500;600;700&display=swap");
              </style>
            </head>
             <body>
            <div style="width:65%; padding: 10px;">
            <div>
                <section  style="background-color: white;">

                <p style="font-size:12pt; margin: 15px 0px 0px 0px; font-family: \'Assistant\', sans-serif;" class="mt-5">Hi,</p>

                    <p style="font-size:12pt; margin: 15px 0px 0px 0px; font-family: \'Assistant\', sans-serif;" class="mt-5">Please click the link ' . $link . ' to reset your password.</p>

					<p style="font-size:12pt;margin: 15px 0px 0px 0px;  font-family: \'Assistant\', sans-serif;" class="mt-3">Best regards,</p>

                    <p style="font-size:12pt;font-size:12pt;margin:0px; padding-top: 0px; font-family: \'Assistant\', sans-serif;">Team</p>

				</section>

                <footer">
                <span style="font-size:12pt;margin: 0px; font-family: \'Assistant\', sans-serif;"><a style="color:blue;" target="_blank" href="https://www.google.com/">www.google.com</a> </span>
            </footer>
            </div>
           </div>
            </body>

            </html>';
                    $mail->AddAddress($user['email']);
                    $mail->send();


                    $otpEntry = forgotpassword::create([
                        'email' => $user['email'],
                        'code' => $code,
                    ]);

                    return response()->json([
                        'status_code' => 200,
                        'message' => 'Reset password link have sent successfully',
                    ]);

                } catch (\Exception $e) {
                    return response()->json([
                        'error' => 'Failed to send OTP',
                        'error_message' => $e->getMessage(),
                    ], 500);
                }

            } else {
                return response()->json([
                    'message' => 'Invalid emailID',
                    'status_code' => 400
                ], 400);
            }
        }
    }

    
    public function resetpassword(Request $request)
    {
        $input = $request->all();
        $validation = Validator::make($input, [
            'code' => 'required',
            'password' => 'required|required_with:confirmpassword|same:confirmpassword',
            'confirmpassword' => 'required',
        ]);

        if ($validation->fails()) {
            return response()->json(['error' => $validation->errors(), 'status_code' => 400], 400);
        } else {
            $code = $request->input('code');
            $password = $request->input('password');
            $confirmpassword = $request->input('confirmpassword');

            $forgotpassword = forgotpassword::where("code", $code)->first();

            if ($forgotpassword) {
                $useremail = $forgotpassword->email;
                $passwordhash = Hash::make($password);

                User::where('email', $useremail)
                    ->update(['password' => $passwordhash]);

                return response()->json([
                    'status_code' => 200,
                    'message' => 'Password has been reset successfully',
                ]);
            } else {
                return response()->json([
                    'message' => 'Invalid Link',
                    'status_code' => 400
                ], 400);
            }
        }
    }
}
