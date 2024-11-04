<?php

namespace App\Http\Services;

use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Validator;

class AuthService
{
    /**
     * Registrar un nuevo usuario.
     */
    public function register(array $data)
    {
        // Validación de datos de entrada (lógica del negocio)
        $validator = Validator::make($data, [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => [
                'required',
                'string',
                'min:8'
            ],
        ]);

        if ($validator->fails()) {
            throw ValidationException::withMessages($validator->errors()->toArray());
        }

        // Crear un nuevo usuario y devolver respuesta
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);
    }

    public function login(array $credentials)
    {
        // Validación de credenciales
        $validator = Validator::make($credentials, [
            'email' => 'required|string|email',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            throw ValidationException::withMessages($validator->errors()->toArray());
        }

        if (!Auth::attempt($credentials)) {
            throw ValidationException::withMessages([
                'email' => ['Las credenciales no son válidas'],
            ]);
        }

        $user = Auth::user();

        // Crear token y guardar en cookie
        $token = $user->createToken('auth_token')->plainTextToken;
        $cookie = Cookie::make('auth_token', $token, 60 * 24, '/', null, true, true, false, 'Strict');
        return ['token' => $token, 'cookie' => $cookie];
    }

    public function logout()
    {
        // Revocar token del usuario autenticado
        Auth::user()->tokens()->delete();

        // Eliminar cookie
        return Cookie::forget('auth_token');
    }
}
