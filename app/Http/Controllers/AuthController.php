<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (auth()->attempt($request->only('email', 'password'))) {
            return response()->json(['message' => 'Login successful.']);
        }

        return response()->json(['message' => 'Invalid credentials.'], 401);
    }

    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'Logout successful.']);
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        return response()->json(['message' => 'Registration successful.']);
    }

    public function refreshToken()
    {
        return response()->json(['token' => auth()->refresh()]);
    }

    public function me()
    {
        return response()->json(auth()->user());
    }

    public function updateProfile(Request $request)
    {
        $user = auth()->user();
        $user->update($request->all());
        return response()->json(['message' => 'Profile updated successfully.']);
    }

    public function deleteAccount()
    {
        auth()->user()->delete();
        return response()->json(['message' => 'Account deleted successfully.']);
    }

    public function sendResetPasswordEmail(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
        ]);

        $user = User::where('email', $request->email)->first();
        if (!$user) {
            return response()->json(['message' => 'User not found.'], 404);
        }

        $token = $user->createToken('password-reset-token')->plainTextToken;
        return response()->json(['message' => 'Password reset link sent.'], 200);
    }

    public function resetPassword($token, Request $request)
    {
        $user = User::whereHas('tokens', function ($query) use ($token) {
            $query->where('token', $token);
        })->first();

        if (!$user) {
            return response()->json(['message' => 'Invalid token.'], 404);
        }

        $request->validate([
            'password' => 'required|confirmed',
        ]);

        $user->password = bcrypt($request->password);
        $user->save();

        return response()->json(['message' => 'Password reset successfully.'], 200);
    }
}
