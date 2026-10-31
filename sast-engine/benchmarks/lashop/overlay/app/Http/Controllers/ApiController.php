<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ApiController extends Controller
{
    public function orders(Request $request)
    {
        $customer = $request->query('customer', '');
        return response()->json(DB::select("SELECT * FROM orders WHERE customer = '$customer'"));
    }

    public function one($id)
    {
        return response()->json(DB::select('SELECT * FROM orders WHERE id = ' . $id));
    }

    public function create(Request $request)
    {
        $data = $request->validate(['customer' => 'required|string', 'item' => 'required|string']);
        DB::insert('INSERT INTO orders (customer, item) VALUES (?, ?)', [$data['customer'], $data['item']]);
        return response()->json(['status' => 'created'], 201);
    }
}
