<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function createUser(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required',
            // 'role' => 'required',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'user_type' => $request->user_type == '1' ? $request->user_type : '2',
            'password' => bcrypt($request->password),
            // 'role' => $request->role,
        ]);

        return response()->json(['message' => 'User created successfully']);
    }

    public function updateUser(Request $request) {
        $request->validate([
            'id' => 'required',
        ]);

        $user = User::find($request->id);

        if (!$user) {
            return response()->json(['error' => 'User not found'], 404);
        }
        $user->update($request->all());
        return response()->json($user);
    }


    public function updatePassword(Request $request) {
        $request->validate([
            'old_password' => 'required',
            'new_password' => 'required|min:6|max:255|',
            'confirm_password' => 'required|same:new_password',
        ]);

        if (!Hash::check($request->old_password, auth()->user()->password)) {
            return response()->json(['error' => 'Old password is incorrect'], 401);
        }

        $user = auth()->user();
        $user->password = bcrypt($request->new_password);
        $user->save();

        return response()->json(['message' => 'Password updated successfully']);
    }
}
