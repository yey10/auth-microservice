<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Exception;
use App\Http\Services\AuthService;

class AuthController extends Controller
{
    protected $authService;

    public function __construct(AuthService $authService)
    {
        $this->authService = $authService;
    }

    /**
     * Método para registrar usuarios
     */
    public function register(Request $request)
    {
        try {
            $user = $this->authService->register($request->all());
            return response()->json(['message' => 'Usuario creado con éxito', 'user' => $user], 201);
        } catch (ValidationException $e) {
            return response()->json(['error' => $e->errors()], 422);
        } catch (Exception $e) {
            return response()->json(['error' => 'Failed to register user', 'message' => $e->getMessage()], 500);
        }
    }

    /**
     * Método para logueo del usuario
     */
    public function login(Request $request)
    {
        $validatedData = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string|min:8',
        ]);

        if ($validatedData->fails()) {
            return response()->json(['error' => $validatedData->errors()], 422);
        }

        try {
            $tokenData = $this->authService->login($validatedData->validated());

            return response()->json([
                'message' => 'Usuario logueado con éxito',
                'access_token' => $tokenData['token'],
                'token_type' => 'Bearer',
                'cookie' => $tokenData['cookie']
            ], 200);
        } catch (ValidationException $e) {
            return response()->json(['error' => $e->errors()], 401);
        } catch (Exception $e) {
            return response()->json(['error' => 'Failed to login', 'message' => $e->getMessage()], 500);
        }
    }

    /**
     * Método para cerrar sesión
     */
    public function logout(Request $request)
    {
        try {
            $cookie = $this->authService->logout();
            return response()->json(['message' => 'Sesión cerrada con éxito'])->withCookie($cookie);
        } catch (Exception $e) {
            return response()->json(['error' => 'Failed to logout', 'message' => $e->getMessage()], 500);
        }
    }

    /**
     * Método para obtener el usuario autenticado 
     */
    public function user(Request $request)
    {
        try {
            return response()->json($request->user(), 200);
        } catch (Exception $e) {
            return response()->json(['error' => 'Failed to retrieve user', 'message' => $e->getMessage()], 500);
        }
    }
}
