<?php


use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;



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
Route::post('forgotpassword', [UserController::class, 'forgotpassword']);
Route::post('resetpassword', [UserController::class, 'resetpassword']);
Route::post('verifyotpresetpassword', [UserController::class, 'verifyotpresetpassword']);
Route::middleware('auth:api')->group(function () {
    Route::post('refreshtoken', [UserController::class, 'refreshtoken']);
    Route::post('logout', [UserController::class, 'logout']);
});
