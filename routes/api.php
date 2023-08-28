<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::post('register', [UserController::class, 'register']);
Route::post('login', [UserController::class, 'login']);
Route::middleware('auth:api')->group(function () {
    Route::post('refreshtoken', [UserController::class, 'refreshtoken']);
    Route::post('logout', [UserController::class, 'logout']);
    Route::post('forgotpassword', [UserController::class, 'forgotpassword']);
    Route::post('resetpassword', [UserController::class, 'resetpassword']);
});
