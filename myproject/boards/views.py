from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from .forms import NewTopicForm, PostForm
from .models import Board, Topic, Post
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.urls import reverse
from django.db.models import Count

def home(request):
    boards = Board.objects.all()
    return render(request, 'home.html', {'boards': boards})


@login_required
def board_topics(request, name):
    board = get_object_or_404(Board, name=name)
    topics = board.topics.order_by('-last_updated').annotate(replies=Count('posts') - 1)
    return render(request, 'topics.html', {'board': board, 'topics': topics})


@login_required
def new_topic(request, name):
    board = get_object_or_404(Board, name=name)
    if request.method == 'POST':
        form = NewTopicForm(request.POST)
        if form.is_valid():
            topic = form.save(commit=False)
            topic.board = board
            topic.starter = request.user
            topic.save()
            Post.objects.create(
                message=form.cleaned_data.get('message'),
                topic=topic,
                created_by=request.user,
                votes=0
            )
            return redirect(reverse('topic_posts', kwargs={'name':name, 'topic_pk':topic.pk}))
    else:
        form = NewTopicForm()
    return render(request, 'new_topic.html', {'board': board, 'form': form})


@login_required
def topic_posts(request, name, topic_pk):
    topic = get_object_or_404(Topic, board__name=name, pk=topic_pk)
    topic.views += 1
    topic.save()
    return render(request, 'topic_posts.html', {'topic': topic})

@login_required
def upvote_post(request, name, topic_pk, post_pk):
    post = get_object_or_404(Post, topic__pk=topic_pk, pk=post_pk)
    post.votes = post.votes + 1
    post.save()
    return redirect(reverse('topic_posts', kwargs={'name':name, 'topic_pk':topic_pk}))


@login_required
def downvote_post(request, name, topic_pk, post_pk):
    post = get_object_or_404(Post, topic__pk=topic_pk, pk=post_pk)
    post.votes = post.votes - 1
    post.save()
    return redirect(reverse('topic_posts', kwargs={'name':name, 'topic_pk':topic_pk}))


@login_required
def reply_topic(request, name, topic_pk):
    topic = get_object_or_404(Topic, board__name=name, pk=topic_pk)
    if request.method == 'POST':
        form = PostForm(request.POST)
        if form.is_valid():
            post = form.save(commit=False)
            post.topic = topic
            post.created_by = request.user
            post.votes = 0
            post.save()
            return redirect('topic_posts', name=name, topic_pk=topic_pk)
    else:
        form = PostForm()
    return render(request, 'reply_topic.html', {'topic': topic, 'form': form})
