<?php

use App\Http\Controllers\ApiController;
use Illuminate\Support\Facades\Route;

Route::get('/orders', [ApiController::class, 'orders']);
Route::get('/orders/{id}', [ApiController::class, 'one'])->whereNumber('id');
Route::post('/orders', [ApiController::class, 'create']);
