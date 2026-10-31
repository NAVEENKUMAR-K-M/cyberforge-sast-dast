<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('products', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->float('price');
        });
        Schema::create('reviews', function (Blueprint $table) {
            $table->id();
            $table->integer('product_id');
            $table->text('body');
        });
        Schema::create('orders', function (Blueprint $table) {
            $table->id();
            $table->string('customer');
            $table->string('item');
        });
        DB::table('products')->insert([
            ['name' => 'Hammer', 'price' => 12.5],
            ['name' => 'Anvil', 'price' => 99.5],
            ['name' => 'Lamp', 'price' => 25.0],
        ]);
        DB::table('orders')->insert([
            ['customer' => 'ada', 'item' => 'Hammer'],
            ['customer' => 'bob', 'item' => 'Anvil'],
        ]);
    }

    public function down(): void
    {
        Schema::dropIfExists('orders');
        Schema::dropIfExists('reviews');
        Schema::dropIfExists('products');
    }
};
