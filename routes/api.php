<?php

use Illuminate\Support\Facades\Route;

Route::group(['prefix' => 'auth', 'namespace' => 'Api'], function () {

    Route::post('register',     'AuthController@register');

    /* ------------------------ For Personal Access Token ----------------------- */
    Route::post('login',        'AuthController@login');
    /* -------------------------------------------------------------------------- */

    Route::group(['middleware' => 'auth:api'], function () {
        Route::get('logout',    'AuthController@logout');
        Route::get('user',      'AuthController@getUser');
    });

   /* ------------------------ For Password Grant Token ------------------------ */
    Route::post('login_grant',  'AuthController@loginGrant');
    Route::post('refresh',      'AuthController@refreshToken');
    /* -------------------------------------------------------------------------- */

    /* -------------------------------- Fallback -------------------------------- */
    Route::any('{segment}', function () {
        return response()->json([
            'error' => 'Invalid url.'
        ]);
    })->where('segment', '.*');
});

Route::get('unauthorized', function () {
    return response()->json([
        'error' => 'Unauthorized.'
    ], 401);
})->name('unauthorized');
