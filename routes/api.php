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
Route::post('refreshtoken', [UserController::class, 'refreshtoken']);
Route::middleware('auth:api')->group(function () {
    Route::get('image', [UserController::class, 'getimage']);
    Route::post('image-upload', [ UserController::class, 'imageUploadPost' ]);
    Route::post('logic', [UserController::class, 'logic_check']);
});
