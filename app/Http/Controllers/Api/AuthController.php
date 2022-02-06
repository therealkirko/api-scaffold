<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Http\Request;
use App\Models\User;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $credentials['email'])->first();
        // check if user exists
        if (!$user || ! Hash::check($credentials['password'], $user->password)) {
            return response()->json([
                'message' => 'The provided credentials do not match.'
            ], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'token' => $token
        ], 201);
    }

    public function register(Request $request)
    {
        // validate request
        $validatedData = $request->validate([
            'name' => 'required|string',
            'country' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed',
        ]);

        // create user
        $validatedData['password'] = Hash::make($validatedData['password']);
        $user = User::create($validatedData);

        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json([
            'token' => $token
        ], 201);
    }

    public function logout()
    {
        // logout user  and revoke token
        auth()->user()->tokens->each(function ($token) {
            $token->delete();
        });

        return response()->json(['message' => 'Successfully logged out'], 200);
    }
}
