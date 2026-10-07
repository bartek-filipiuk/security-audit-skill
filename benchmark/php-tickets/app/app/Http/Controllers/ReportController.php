<?php

namespace App\Http\Controllers;

use App\Models\Ticket;
use Illuminate\Http\Request;

class ReportController extends Controller
{
    public function tickets(Request $request)
    {
        $from = $request->date('from') ?? now()->subMonth();

        $rows = Ticket::query()
            ->selectRaw('status, count(*) as total')
            ->whereRaw('created_at >= ?', [$from])
            ->groupBy('status')
            ->get();

        return view('admin.reports', ['rows' => $rows, 'from' => $from]);
    }

    public function export(Request $request)
    {
        $tickets = Ticket::with('user:id,name,email')->latest()->limit(5000)->get();

        $csv = $tickets->map(fn ($t) => implode(',', [
            $t->id,
            $t->status,
            $t->user->email,
            str_replace(',', ' ', $t->subject),
        ]))->prepend('id,status,email,subject')->implode("\n");

        return response($csv, 200, ['Content-Type' => 'text/csv']);
    }
}
