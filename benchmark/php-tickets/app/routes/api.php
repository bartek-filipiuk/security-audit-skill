<?php

use App\Http\Controllers\Api\TicketApiController;
use App\Http\Controllers\ReportController;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/tickets', [TicketApiController::class, 'index']);
    Route::get('/tickets/{ticket}', [TicketApiController::class, 'show']);
});

Route::get('/reports/export', [ReportController::class, 'export']);
