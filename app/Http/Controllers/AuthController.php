<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (auth()->attempt($request->only('email', 'password'))) {
            $user = auth()->user();
            $name = $user->name;
            $token = $request->user()->createToken($name)->plainTextToken;

            // Store token in Memcached (set expiration time, e.g., 1 hour)
            Cache::put("user_token_{$user->id}", $token, now()->addMinutes(60));

            return response()->json([
                'user' => auth()->user(),
                'access_token' => $token,
                'name' => $name,
                'message' => 'Login successful.',
            ]);
        }

        return response()->json(['message' => 'Invalid credentials.'], 401);
    }


    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required',
            'role' => 'required',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'role' => $request->role,
        ]);

        return response()->json(['message' => 'User created successfully']);
    }

    public function logout(Request $request)
    {
        $user = Auth::user();

        if ($user) {
            // Delete token from Memcached
            Cache::forget("user_token_{$user->id}");
            $request->user()->currentAccessToken()->delete(); // Deletes the current token
            return response()->json(['message' => 'Logged out successfully'], 200);
        }

        return response()->json(['message' => 'User not authenticated'], 401);
    }

    public function logoutFromAllDevices(Request $request)
    {
        $request->user()->tokens()->delete(); // Deletes all tokens for the user
        return response()->json(['message' => 'Logged out from all devices'], 200);
    }

    public function me()
    {
        return response()->json(auth()->user());
    }

    public function refreshToken(Request $request)
    {
        $token = $request->user()->createToken('refresh-token')->plainTextToken;
        return response()->json(['token' => $token]);
    }

    public function createToken(Request $request)
    {
        $token = $request->user()->createToken($request->token_name);
        return response()->json(['token' => $token->plainTextToken]);
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

        // Generate a reset token (Not using Sanctum's hashed token)
        $token = Str::random(60);

        // Store the token in a password_resets table
        DB::table('password_resets')->updateOrInsert(
            ['email' => $user->email],
            ['token' => bcrypt($token), 'created_at' => now()]
        );

        // Send email (implement actual email logic)
        // Mail::to($user->email)->send(new ResetPasswordMail($token));

        return response()->json(['message' => 'Password reset link sent.'], 200);
    }

    public function resetPassword($token, Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'token' => 'required',
            'password' => 'required|confirmed',
        ]);

        // Find the reset token in the database
        $resetRequest = DB::table('password_resets')
            ->where('email', $request->email)
            ->first();

        if (!$resetRequest || !password_verify($request->token, $resetRequest->token)) {
            return response()->json(['message' => 'Invalid token.'], 404);
        }

        // Update password
        $user = User::where('email', $request->email)->first();
        $user->password = bcrypt($request->password);
        $user->save();

        // Delete the used reset token
        DB::table('password_resets')->where('email', $request->email)->delete();

        return response()->json(['message' => 'Password reset successfully.'], 200);
    }
}
