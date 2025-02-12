<?php

use App\Http\Middleware\CheckAuthToken;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->alias([
            'checkAuthToken' => CheckAuthToken::class
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions) {

        // Handle generic exceptions
        $exceptions->render(\Throwable::class, function (\Throwable $e, $request) {
            return response()->json([
                'message' => 'Something went wrong',
                'error' => $e->getMessage(),
            ], 500);
        });
    })->create();
