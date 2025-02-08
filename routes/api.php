<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;


Route::post('/login', [AuthController::class, 'login']);
Route::post('/register', [AuthController::class, 'register']);

// Auth Middleware for protected routes
Route::middleware('auth:sanctum')->group(function () {

    Route::prefix('auth')->group(function () {
        Route::post('/logout', [AuthController::class, 'logout']);
        Route::post('/refresh-token', [AuthController::class, 'refreshToken']);
        Route::post('/create-token', [AuthController::class, 'createToken']);
        Route::post('/update-profile', [AuthController::class, 'updateProfile']);
        Route::post('/delete-profile', [AuthController::class, 'deleteAccount']);
        Route::post('/send-reset-password-email', [AuthController::class, 'sendResetPasswordEmail']);
        Route::post('/reset-password', [AuthController::class, 'resetPassword']);
    });

    Route::prefix('user')->group(function () {
        Route::get('/me', [UserController::class, 'me']);
        Route::post('/create', [UserController::class, 'createUser']);
        Route::post('/update', [UserController::class, 'updateUser']);
        Route::post('/update-password', [UserController::class, 'updatePassword']);
    });

});
