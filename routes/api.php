<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\AdminController;
use App\Http\Controllers\CommonController;
use Illuminate\Support\Facades\Route;
use App\Enums\UserRole;


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

    // Route accessible only by admins
    Route::middleware('role:' . UserRole::ADMIN->value)->group(function () {
        Route::get('/admin-only', [AdminController::class, 'index']);
    });

    // Route accessible only by users
    Route::middleware('role:' . UserRole::USER->value)->group(function () {
        Route::get('/user-only', [UserController::class, 'index']);
    });

    // Route accessible by both admins and users
    Route::middleware('role:' . UserRole::ADMIN->value . ',' . UserRole::USER->value)->group(function () {
        Route::get('/admin-and-user', [CommonController::class, 'index']);
    });

});
