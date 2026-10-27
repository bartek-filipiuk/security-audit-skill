@extends('layouts.app')

@section('content')
<article class="ticket">
    <h1>{{ $ticket->subject }}</h1>
    <p class="meta">#{{ $ticket->id }} · {{ $ticket->status }} · {{ $ticket->priority }}</p>

    <div class="ticket-body">{!! nl2br(e($ticket->body)) !!}</div>

    <ul class="attachments">
        @foreach ($ticket->attachments as $file)
            <li><a href="{{ Storage::disk('public')->url($file->path) }}">{{ $file->name }}</a></li>
        @endforeach
    </ul>

    <section class="comments">
        @foreach ($ticket->comments as $comment)
            <div class="comment">
                <strong>{{ $comment->author->name }}</strong>
                <div class="comment-body">{!! $comment->body !!}</div>
            </div>
        @endforeach
    </section>

    <form method="POST" action="{{ route('comments.store', $ticket) }}">
        @csrf
        <textarea name="body" required></textarea>
        <button type="submit">Reply</button>
    </form>
</article>
@endsection
