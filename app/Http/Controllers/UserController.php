<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{

    public function register(Request $request)
    {
        $this->validate($request, [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $token = $user->createToken('Laravel8PassportAuth')->accessToken;
        $token = $user->createToken('Laravel8PassportAuth')->refreshtoken;
        return response()->json(['token' => $token], 200);
    }

    /**
     * Login Req
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 401);
        } else {

            $data = [
                'grant_type' => 'password',
                'client_id' => getenv('PASSPORT_PERSONAL_GRAND_CLIENT_ID'),
                'client_secret' => getenv('PASSPORT_PERSONAL_GRAND_CLIENT_SECRET'),
                'username' => request('username'),
                'password' => request('password'),
            ];

            $request = Request::create('/oauth/token', 'POST', $data);
            return app()->handle($request);
        }
    }

    public function userInfo()
    {

        $user = auth()->user();

        return response()->json(['user' => $user], 200);
    }

    public function refreshtoken(Request $request)
    {
        $data = [
            'grant_type' => 'refresh_token',
            'refresh_token' => request('refresh_token'),
            'client_id' => getenv('PASSPORT_PERSONAL_GRAND_CLIENT_ID'),
            'client_secret' => getenv('PASSPORT_PERSONAL_GRAND_CLIENT_SECRET'),
        ];

        $request = Request::create('/oauth/token', 'POST', $data);


        return app()->handle($request);
    }



    public function imageUploadPost(Request $request)
    {
        $request->validate([
            'image' => 'required|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
        ]);
        if ($request->hasfile('image')) {
            $file = $request->file('image');
            $imageName = time() . $file->getClientOriginalName();
            // dd($imageName );
            $filePath = 'images/' . $imageName;
            Storage::disk('s3')->put($filePath, file_get_contents($file));

            $user  =  new user;
            $user->imagename = $imageName;
            $user->save();
            return response()->json(['success' => 'You have successfully upload image.']);
        }
    }

    public function getimage(Request $request)
    {
        // Make sure you have s3 as your disk driver
        $url = Storage::disk('s3')->temporaryUrl(
            '1675342255image',
            Carbon::now()->addMinutes(5)
        );
        return response()->json(['url' => $url]);
    }



    public function logic_check(Request $request)
    {

        $statement = 10;
    //    dd($request->condtion);
       if($request->condition == "isequalto" && $request->statement == $statement){
       

       }
    }
}
