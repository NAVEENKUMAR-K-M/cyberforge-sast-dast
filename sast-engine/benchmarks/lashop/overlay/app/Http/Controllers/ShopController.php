<?php

namespace App\Http\Controllers;

use App\Models\Product;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ShopController extends Controller
{
    public function home()
    {
        return view('home');
    }

    public function search(Request $request)
    {
        $q = $request->input('q', '');
        $rows = DB::select("SELECT id, name, price FROM products WHERE name LIKE '%" . $q . "%'");
        return view('search', ['q' => $q, 'rows' => $rows]);
    }

    public function show($id)
    {
        $rows = DB::select('SELECT * FROM products WHERE id = ' . $id);
        $reviews = DB::select('SELECT body FROM reviews WHERE product_id = ?', [$id]);
        return view('product', ['product' => $rows[0] ?? null, 'reviews' => $reviews, 'id' => $id]);
    }

    public function review(Request $request, $id)
    {
        DB::insert('INSERT INTO reviews (product_id, body) VALUES (?, ?)', [$id, $request->input('body')]);
        return redirect('/products/' . $id);
    }

    public function download(Request $request)
    {
        return response()->download(storage_path('app/' . $request->query('file')));
    }

    public function go(Request $request)
    {
        return redirect($request->query('url', '/'));
    }

    public function welcome(Request $request)
    {
        $allowed = ['/', '/search', '/profile'];
        $to = $request->query('to', '/');
        return redirect(in_array($to, $allowed, true) ? $to : '/');
    }

    public function ping(Request $request)
    {
        $out = null;
        if ($request->isMethod('post')) {
            $out = shell_exec('ping -c 1 -W 1 ' . $request->input('host') . ' 2>&1');
        }
        return view('ping', ['out' => $out]);
    }

    public function profile(Request $request)
    {
        return view('profile', ['name' => $request->query('name', 'guest')]);
    }

    public function byName(Request $request)
    {
        return response()->json(Product::where('name', $request->query('name'))->get());
    }
}
