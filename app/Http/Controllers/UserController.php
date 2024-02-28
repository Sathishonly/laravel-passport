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
            'password' => [
                'required',
                'min:8',
                'max:16',
                'regex:/^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]+$/'
            ]
        ]);
        if ($validation->fails()) {
            return response()->json(['error' => $validation->errors(), 'status_code' => 400], 400);
        } else {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            $token = $user->createToken('LaravelPassportAuth')->accessToken;
            return response()->json(['status_code' => 200, 'token' => $token]);
        }
    }


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
                    $token = $user->createToken('LaravelPassportAuth')->accessToken;
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
        $token = $user->createToken('LaravelPassportAuth');
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


    //sent otp for forgotpassword 
    public function sentotpforgotpassword(Request $request)
    {
        require base_path("vendor/autoload.php");
        $mail = new PHPMailer(true);

        $input = $request->all();
        $validation = Validator::make($input, [
            'email' => 'required',
        ]);

        if ($validation->fails()) {
            $errors = $validation->errors()->first();
            return response()->json(['error_code' => $errors, 'status_code' => 400]);
        } else {
            $email = $request->input('email');

            $user = User::where('email', $email)->first();
            if ($user) {
                $otp = mt_rand(100000, 999999);

                try {
                    $existingOTP = forgotpassword::where('email', $email)->first();
                    if ($existingOTP) {
                        $existingOTP->delete();
                    }
                    $mail->SMTPDebug = 0;
                    $mail->isSMTP();
                    $mail->Host = 'smtp.gmail.com'; //  smtp host
                    $mail->SMTPAuth = true;
                    $mail->Username = 'example@gmail.com'; //  sender username
                    $mail->Password = '*******'; // sender password
                    $mail->SMTPSecure = 'tls'; // encryption - ssl/tls
                    $mail->Port = 587; // port - 587/465
                    $mail->setFrom('example@gmail.com', 'Forgot Password');
                    $mail->addAddress($email);
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
                        <p style="font-size:12pt; margin: 15px 0px 0px 0px; font-family: \'Assistant\', sans-serif;" class="mt-5">Your OTP is ' . $otp . ' to complete the verification process.</p>
                        <p style="font-size:12pt; margin: 15px 0px 0px 0px; font-family: \'Assistant\', sans-serif;" class="mt-5">Enter the OTP in the designated field to proceed with your application.</p>
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
                    $mail->send();
                    $otpEntry = forgotpassword::create([
                        'email' => $email,
                        'otp' => $otp,
                    ]);
                    return response()->json([
                        'status_code' => 200,
                        'message' => 'OTP sent successfully, please check your inbox.',
                    ]);
                } catch (\Exception $e) {
                    return response()->json([
                        'error' => 'Failed to send OTP',
                        'error_code' => $e->getMessage(),
                    ], 500);
                }
            } else {
                return response()->json([
                    'status_code' => 400,
                    'message' => "We couldn't find this email",
                ]);
            }

        }
    }


    //verify otp for forgotpassword
    public function verifyotpresetpassword(Request $request)
    {
        $input = $request->all();
        $validation = Validator::make($input, [
            'email' => 'required|email',
            'otp' => 'required',
        ]);

        if ($validation->fails()) {
            $errors = [];
            $messageBag = $validation->errors();
            foreach ($messageBag->keys() as $fieldKey) {
                $errors = $messageBag->first($fieldKey);
                break;
            }
            return response()->json(['error_code' => $errors, 'status_code' => 400]);
        } else {
            $otp = (int) $request->input('otp');
            $email = $request->email;

            $forgetpassword = forgotpassword::where('email', $email)->first();
            if (!$forgetpassword) {
                return response()->json([
                    'status_code' => 400,
                    'error_code' => 'Invalid OTP',
                ]);
            }
            if ($otp == $forgetpassword->otp) {
                return response()->json(['status_code' => 200, 'message' => "OTP Verified"]);
            } else {
                return response()->json([
                    'status_code' => 400,
                    'error_code' => 'Invalid OTP',
                ]);
            }
        }
    }


    //reset password for user
    public function resetpassword(Request $request)
    {
        $input = $request->all();
        $validation = Validator::make($input, [
            'email' => 'required|email',
            'otp' => 'required',
            'password' => [
                'required',
                'min:8',
                'max:16',
                'regex:/^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]+$/'
            ]
        ]);

        if ($validation->fails()) {
            return response()->json(['error' => $validation->errors(), 'status_code' => 400], 400);
        } else {
            $otp = $request->input('otp');
            $password = $request->input('password');
            $email = $request->email;
            $forgotpassword = forgotpassword::where("otp", $otp)->first();
            if (!$forgotpassword) {
                return response()->json([
                    'status_code' => 400,
                    'error_code' => 'Invalid OTP',
                ]);
            }

            if ($forgotpassword) {
                $forgotpassword->delete();
                $passwordhash = Hash::make($password);
                User::where('email', $email)
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


    //change password
    public function changepassword(Request $request)
    {
        $input = $request->all();

        $validation = Validator::make($input, [
            'userId' => 'required',
            'oldpassword' => 'required',
            'newpassword' => 'required|same:confirmpassword',
            'confirmpassword' => 'required',
        ]);
        if ($validation->fails()) {
            return response()->json(['error' => $validation->errors(), 'status_code' => 400]);
        } else {
            $userId = $input['userId'];
            $user = User::find($userId);
            if (!$user) {
                return response()->json(['error' => 'User not found', 'status_code' => 301]);
            }

            if (!Hash::check($input['oldpassword'], $user->password)) {
                return response()->json(['error' => 'Incorrect old password', 'status_code' => 401]);
            } else {
                $newPasswordHash = Hash::make($input['newpassword']);
                $user->password = $newPasswordHash;
                $user->save();
                return response()->json(['message' => 'Password changed successfully', 'status_code' => 200]);
            }
        }
    }
}
