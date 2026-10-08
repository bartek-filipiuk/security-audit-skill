<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreTicketRequest;
use App\Models\Ticket;
use Illuminate\Http\Request;

class TicketController extends Controller
{
    public function index(Request $request)
    {
        $q = $request->query('q');

        $tickets = $request->user()->tickets()
            ->when($q, fn ($query) => $query->whereRaw("subject LIKE '%{$q}%'"))
            ->latest()
            ->paginate(20);

        return view('tickets.index', ['tickets' => $tickets, 'q' => $q]);
    }

    public function store(StoreTicketRequest $request)
    {
        $ticket = Ticket::create($request->validated() + ['user_id' => $request->user()->id]);

        return redirect()->route('tickets.show', $ticket->id);
    }

    public function show(Request $request, int $id)
    {
        $ticket = Ticket::with(['comments.author', 'attachments'])->findOrFail($id);

        return view('tickets.show', ['ticket' => $ticket]);
    }

    public function update(Request $request, Ticket $ticket)
    {
        $this->authorize('update', $ticket);

        $data = $request->validate([
            'subject' => ['required', 'string', 'max:200'],
            'priority' => ['required', 'in:low,normal,high'],
        ]);
        $ticket->update($data);

        return redirect()->route('tickets.show', $ticket->id);
    }
}
