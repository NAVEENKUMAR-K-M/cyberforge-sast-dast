<?php

use App\Http\Controllers\ShopController;
use Illuminate\Support\Facades\Route;

Route::get('/', [ShopController::class, 'home'])->name('home');
Route::get('/search', [ShopController::class, 'search']);
Route::get('/products/{id}', [ShopController::class, 'show']);
Route::post('/products/{id}/reviews', [ShopController::class, 'review']);
Route::get('/download', [ShopController::class, 'download']);
Route::get('/go', [ShopController::class, 'go']);
Route::get('/welcome', [ShopController::class, 'welcome']);
Route::match(['get', 'post'], '/tools/ping', [ShopController::class, 'ping']);
Route::get('/profile', [ShopController::class, 'profile']);
Route::get('/products-by-name', [ShopController::class, 'byName']);
