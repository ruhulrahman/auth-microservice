<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;

// Route::get('/user', function (Request $request) {
//     return $request->user();
// })->middleware('auth:sanctum');

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });

    Route::post('/logout', function (Request $request) {
        $request->user()->tokens()->delete();
        return response()->json(['message' => 'Logged out successfully.']);
    });

    Route::post('/tokens/create', function (Request $request) {
        $token = $request->user()->createToken($request->token_name);

        return ['token' => $token->plainTextToken];
    });

    Route::post('/refresh-token', function (Request $request) {
        $token = $request->user()->createToken('refresh-token')->plainTextToken;
        return response()->json(['token' => $token]);
    });

    Route::post('/update-user', function (Request $request) {
        $request->user()->update($request->all());
        return response()->json(['message' => 'User updated successfully.']);
    });

    Route::post('/update-password', function (Request $request) {
        $request->user()->update([
            'password' => Hash::make($request->password)
        ]);
        return response()->json(['message' => 'Password updated successfully.']);
    });
});
