<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Auth;

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


}
