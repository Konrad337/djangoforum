from django.urls import reverse, resolve
from django.test import TestCase
from .views import home, board_topics, new_topic
from .models import Board
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404
from django.contrib.auth.models import User
from .views import new_topic
from .models import Board, Topic, Post
from .forms import NewTopicForm
from django.db.utils import IntegrityError
from django import forms
from .templatetags.form_tags import field_type, input_class
from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import PasswordResetForm
from django.core import mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.forms import SetPasswordForm
from .views import topic_posts


class HomeTests(TestCase):

    def test_home_view_status_code(self):
        url = reverse('home')
        response = self.client.get(url)
        self.assertEquals(response.status_code, 200)


    def test_home_url_resolves_home_view(self):
        view = resolve('/')
        self.assertEquals(view.func, home)

class BoardTopicsTestsNoLogin(TestCase):

    def setUp(self):
        Board.objects.create(name='Django', description='Django board.')


    def test_no_double_names(self):
        with self.assertRaises(IntegrityError):
            Board.objects.create(name='Django', description='Django board.')


    def test_board_topics_view_success_status_code(self):
        url = reverse('board_topics', kwargs={'name': "Django"})
        response = self.client.get(url)
        self.assertEquals(response.status_code, 302)


    def test_board_topics_view_not_found_status_code(self):
        url = reverse('board_topics', kwargs={'name': "sssssssssssssssssssssssssssssssssssss"})
        response = self.client.get(url)
        self.assertEquals(response.status_code, 302)




class BoardTopicsTests(TestCase):

    def setUp(self):
        url = reverse('signup')
        data = {
            'username': 'john',
            'email': 'john@doe.com',
            'password1': 'abcdef123456',
            'password2': 'abcdef123456',
            'security_question': 'Whats my name?',
            'answer': 'john'

        }
        self.response = self.client.post(url, data)
        self.home_url = reverse('home')
        Board.objects.create(name='Django', description='Django board.')


    def test_no_double_names(self):
        with self.assertRaises(IntegrityError):
            Board.objects.create(name='Django', description='Django board.')


    def test_board_topics_view_success_status_code(self):
        url = reverse('board_topics', kwargs={'name': "Django"})
        response = self.client.get(url)
        self.assertEquals(response.status_code, 200)


    def test_board_topics_view_not_found_status_code(self):
        url = reverse('board_topics', kwargs={'name': "sssssssssssssssssssssssssssssssssssss"})
        response = self.client.get(url)
        self.assertEquals(response.status_code, 404)


    def test_board_topics_url_resolves_board_topics_view(self):
        view = resolve('/boards/Django/')
        self.assertEquals(view.func, board_topics)


    def test_board_topics_view_contains_link_back_to_homepage(self):
        board_topics_url = reverse('board_topics', kwargs={'name': "Django"})
        response = self.client.get(board_topics_url)
        homepage_url = reverse('home')
        self.assertContains(response, 'href="{0}"'.format(homepage_url))

class NewTopicTestsNoLogin(TestCase):


    def setUp(self):
        Board.objects.create(name='Django', description='Django board.')


    def test_new_topic_view_success_status_code(self):
        url = reverse('new_topic', kwargs={'name': 'Django'})
        response = self.client.get(url)
        self.assertEquals(response.status_code, 302)


    def test_new_topic_invalid_post_data(self):
        '''
        Invalid post data should not redirect
        The expected behavior is to show the form again with validation errors
        '''
        url = reverse('new_topic', kwargs={'name': 'Django'})
        response = self.client.post(url, {})
        self.assertEquals(response.status_code, 302)


    def test_new_topic_invalid_post_data_empty_fields(self):
        '''
        Invalid post data should not redirect
        The expected behavior is to show the form again with validation errors
        '''
        url = reverse('new_topic', kwargs={'name': 'Django'})
        data = {
            'subject': '',
            'message': ''
        }
        response = self.client.post(url, data)
        self.assertEquals(response.status_code, 302)
        self.assertFalse(Topic.objects.exists())
        self.assertFalse(Post.objects.exists())


class NewTopicTests(TestCase):


    def setUp(self):
        url = reverse('signup')
        data = {
            'username': 'john',
            'email': 'john@doe.com',
            'password1': 'abcdef123456',
            'password2': 'abcdef123456',
            'security_question': 'Whats my name?',
            'answer': 'john'

        }
        self.response = self.client.post(url, data)
        Board.objects.create(name='Django', description='Django board.')


    def test_new_topic_view_success_status_code(self):
        url = reverse('new_topic', kwargs={'name': 'Django'})
        response = self.client.get(url)
        self.assertEquals(response.status_code, 200)


    def test_new_topic_view_not_found_status_code(self):
        url = reverse('new_topic', kwargs={'name': 'eeeeeeeeeeeeee'})
        response = self.client.get(url)
        self.assertEquals(response.status_code, 404)


    def test_new_topic_url_resolves_new_topic_view(self):
        view = resolve('/boards/Django/new/')
        self.assertEquals(view.func, new_topic)


    def test_new_topic_view_contains_link_back_to_board_topics_view(self):
        new_topic_url = reverse('new_topic', kwargs={'name': 'Django'})
        board_topics_url = reverse('board_topics', kwargs={'name': 'Django'})
        response = self.client.get(new_topic_url)
        self.assertContains(response, 'href="{0}"'.format(board_topics_url))


    def test_board_topics_view_contains_navigation_links(self):
        board_topics_url = reverse('board_topics', kwargs={'name': 'Django'})
        homepage_url = reverse('home')
        new_topic_url = reverse('new_topic', kwargs={'name': 'Django'})

        response = self.client.get(board_topics_url)

        self.assertContains(response, 'href="{0}"'.format(homepage_url))
        self.assertContains(response, 'href="{0}"'.format(new_topic_url))


    def test_csrf(self):
        url = reverse('new_topic', kwargs={'name': 'Django'})
        response = self.client.get(url)
        self.assertContains(response, 'csrfmiddlewaretoken')


    def test_new_topic_valid_post_data(self):
        url = reverse('new_topic', kwargs={'name': 'Django'})
        data = {
            'subject': 'Test title',
            'message': 'Lorem ipsum dolor sit amet'
        }
        response = self.client.post(url, data)
        self.assertTrue(Topic.objects.exists())
        self.assertTrue(Post.objects.exists())


    def test_new_topic_invalid_post_data(self):
        '''
        Invalid post data should not redirect
        The expected behavior is to show the form again with validation errors
        '''
        url = reverse('new_topic', kwargs={'name': 'Django'})
        response = self.client.post(url, {})
        form = response.context.get('form')
        self.assertEquals(response.status_code, 200)
        self.assertTrue(form.errors)


    def test_new_topic_invalid_post_data_empty_fields(self):
        '''
        Invalid post data should not redirect
        The expected behavior is to show the form again with validation errors
        '''
        url = reverse('new_topic', kwargs={'name': 'Django'})
        data = {
            'subject': '',
            'message': ''
        }
        response = self.client.post(url, data)
        self.assertEquals(response.status_code, 200)
        self.assertFalse(Topic.objects.exists())
        self.assertFalse(Post.objects.exists())


    def test_contains_form(self):
        url = reverse('new_topic', kwargs={'name': 'Django'})
        response = self.client.get(url)
        form = response.context.get('form')
        self.assertIsInstance(form, NewTopicForm)



class ExampleForm(forms.Form):
    name = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput())
    class Meta:
        fields = ('name', 'password')



class FieldTypeTests(TestCase):
    def test_field_widget_type(self):
        form = ExampleForm()
        self.assertEquals('TextInput', field_type(form['name']))
        self.assertEquals('PasswordInput', field_type(form['password']))



class InputClassTests(TestCase):
    def test_unbound_field_initial_state(self):
        form = ExampleForm()
        self.assertEquals('form-control ', input_class(form['name']))


    def test_valid_bound_field(self):
        form = ExampleForm({'name': 'john', 'password': '123'})
        self.assertEquals('form-control is-valid', input_class(form['name']))
        self.assertEquals('form-control ', input_class(form['password']))


    def test_invalid_bound_field(self):
        form = ExampleForm({'name': '', 'password': '123'})
        self.assertEquals('form-control is-invalid', input_class(form['name']))


class PasswordResetTests(TestCase):
    def setUp(self):
        url = reverse('password_reset')
        self.response = self.client.get(url)

    def test_status_code(self):
        self.assertEquals(self.response.status_code, 200)

    def test_view_function(self):
        view = resolve('/reset/')
        self.assertEquals(view.func.view_class, auth_views.PasswordResetView)

    def test_csrf(self):
        self.assertContains(self.response, 'csrfmiddlewaretoken')

    def test_contains_form(self):
        form = self.response.context.get('form')
        self.assertIsInstance(form, PasswordResetForm)

    def test_form_inputs(self):
        '''
        The view must contain two inputs: csrf and email
        '''
        self.assertContains(self.response, '<input', 2)
        self.assertContains(self.response, 'type="email"', 1)



class SuccessfulPasswordResetTests(TestCase):
    def setUp(self):
        email = 'john@doe.com'
        User.objects.create_user(username='john', email=email, password='123abcdef')
        url = reverse('password_reset')
        self.response = self.client.post(url, {'email': email})

    def test_redirection(self):
        '''
        A valid form submission should redirect the user to `password_reset_done` view
        '''
        url = reverse('password_reset_done')
        self.assertRedirects(self.response, url)

    def test_send_password_reset_email(self):
        self.assertEqual(1, len(mail.outbox))



class InvalidPasswordResetTests(TestCase):
    def setUp(self):
        url = reverse('password_reset')
        self.response = self.client.post(url, {'email': 'donotexist@email.com'})

    def test_redirection(self):
        '''
        Even invalid emails in the database should
        redirect the user to `password_reset_done` view
        '''
        url = reverse('password_reset_done')
        self.assertRedirects(self.response, url)

    def test_no_reset_email_sent(self):
        self.assertEqual(0, len(mail.outbox))



class PasswordResetMailTests(TestCase):
    def setUp(self):
        User.objects.create_user(username='john', email='john@doe.com', password='123')
        self.response = self.client.post(reverse('password_reset'), { 'email': 'john@doe.com' })
        self.email = mail.outbox[0]

    def test_email_subject(self):
        self.assertEqual('[Django Boards] Please reset your password', self.email.subject)

    def test_email_body(self):
        context = self.response.context
        token = context.get('token')
        uid = context.get('uid')
        password_reset_token_url = reverse('password_reset_confirm', kwargs={
            'uidb64': uid,
            'token': token
        })
        self.assertIn(password_reset_token_url, self.email.body)
        self.assertIn('john', self.email.body)
        self.assertIn('john@doe.com', self.email.body)

    def test_email_to(self):
        self.assertEqual(['john@doe.com',], self.email.to)



class PasswordResetDoneTests(TestCase):
    def setUp(self):
        url = reverse('password_reset_done')
        self.response = self.client.get(url)

    def test_status_code(self):
        self.assertEquals(self.response.status_code, 200)

    def test_view_function(self):
        view = resolve('/reset/done/')
        self.assertEquals(view.func.view_class, auth_views.PasswordResetDoneView)


class PasswordResetConfirmTests(TestCase):
    def setUp(self):
        user = User.objects.create_user(username='john', email='john@doe.com', password='123abcdef')

        '''
        create a valid password reset token
        based on how django creates the token internally:
        https://github.com/django/django/blob/1.11.5/django/contrib/auth/forms.py#L280
        '''
        self.uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()
        self.token = default_token_generator.make_token(user)

        url = reverse('password_reset_confirm', kwargs={'uidb64': self.uid, 'token': self.token})
        self.response = self.client.get(url, follow=True)

    def test_status_code(self):
        self.assertEquals(self.response.status_code, 200)

    def test_view_function(self):
        view = resolve('/reset/{uidb64}/{token}/'.format(uidb64=self.uid, token=self.token))
        self.assertEquals(view.func.view_class, auth_views.PasswordResetConfirmView)

    def test_csrf(self):
        self.assertContains(self.response, 'csrfmiddlewaretoken')

    def test_contains_form(self):
        form = self.response.context.get('form')
        self.assertIsInstance(form, SetPasswordForm)

    def test_form_inputs(self):
        '''
        The view must contain two inputs: csrf and two password fields
        '''
        self.assertContains(self.response, '<input', 3)
        self.assertContains(self.response, 'type="password"', 2)


class InvalidPasswordResetConfirmTests(TestCase):
    def setUp(self):
        user = User.objects.create_user(username='john', email='john@doe.com', password='123abcdef')
        uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()
        token = default_token_generator.make_token(user)

        '''
        invalidate the token by changing the password
        '''
        user.set_password('abcdef123')
        user.save()

        url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        self.response = self.client.get(url)

    def test_status_code(self):
        self.assertEquals(self.response.status_code, 200)

    def test_html(self):
        password_reset_url = reverse('password_reset')
        self.assertContains(self.response, 'invalid password reset link')
        self.assertContains(self.response, 'href="{0}"'.format(password_reset_url))




class PasswordResetCompleteTests(TestCase):
    def setUp(self):
        url = reverse('password_reset_complete')
        self.response = self.client.get(url)

    def test_status_code(self):
        self.assertEquals(self.response.status_code, 200)

    def test_view_function(self):
        view = resolve('/reset/complete/')
        self.assertEquals(view.func.view_class, auth_views.PasswordResetCompleteView)



class PasswordResetConfirmTests(TestCase):
    def setUp(self):
        user = User.objects.create_user(username='john', email='john@doe.com', password='123abcdef')

        '''
        create a valid password reset token
        based on how django creates the token internally:
        https://github.com/django/django/blob/1.11.5/django/contrib/auth/forms.py#L280
        '''
        self.uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()
        self.token = default_token_generator.make_token(user)

        url = reverse('password_reset_confirm', kwargs={'uidb64': self.uid, 'token': self.token})
        self.response = self.client.get(url, follow=True)

    def test_status_code(self):
        self.assertEquals(self.response.status_code, 200)

    def test_view_function(self):
        view = resolve('/reset/{uidb64}/{token}/'.format(uidb64=self.uid, token=self.token))
        self.assertEquals(view.func.view_class, auth_views.PasswordResetConfirmView)

    def test_csrf(self):
        self.assertContains(self.response, 'csrfmiddlewaretoken')

    def test_contains_form(self):
        form = self.response.context.get('form')
        self.assertIsInstance(form, SetPasswordForm)

    def test_form_inputs(self):
        '''
        The view must contain two inputs: csrf and two password fields
        '''
        self.assertContains(self.response, '<input', 3)
        self.assertContains(self.response, 'type="password"', 2)


class InvalidPasswordResetConfirmTests(TestCase):
    def setUp(self):
        user = User.objects.create_user(username='john', email='john@doe.com', password='123abcdef')
        uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()
        token = default_token_generator.make_token(user)

        '''
        invalidate the token by changing the password
        '''
        user.set_password('abcdef123')
        user.save()

        url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        self.response = self.client.get(url)

    def test_status_code(self):
        self.assertEquals(self.response.status_code, 200)

    def test_html(self):
        password_reset_url = reverse('password_reset')
        self.assertContains(self.response, 'invalid password reset link')
        self.assertContains(self.response, 'href="{0}"'.format(password_reset_url))


class LoginRequiredPasswordChangeTests(TestCase):
    def test_redirection(self):
        url = reverse('password_change')
        login_url = reverse('login')
        response = self.client.get(url)
        self.assertRedirects(response, f'{login_url}?next={url}')



class PasswordChangeTestCase(TestCase):
    def setUp(self, data={}):
        self.user = User.objects.create_user(username='john', email='john@doe.com', password='old_password')
        self.url = reverse('password_change')
        self.client.login(username='john', password='old_password')
        self.response = self.client.post(self.url, data)


class PasswordChangeTestCase(TestCase):
    def setUp(self, data={}):
        self.user = User.objects.create_user(username='john', email='john@doe.com', password='old_password')
        self.url = reverse('password_change')
        self.client.login(username='john', password='old_password')
        self.response = self.client.post(self.url, data)



class LoginRequiredNewTopicTests(TestCase):
    def setUp(self):
        Board.objects.create(name='Django', description='Django board.')
        self.url = reverse('new_topic', kwargs={'name': 'Django'})
        self.response = self.client.get(self.url)

    def test_redirection(self):
        login_url = reverse('login')
        self.assertRedirects(self.response, '{login_url}?next={url}'.format(login_url=login_url, url=self.url))



class TopicPostsTests(TestCase):
    def setUp(self):
        url = reverse('signup')
        data = {
            'username': 'john',
            'email': 'john@doe.com',
            'password1': 'abcdef123456',
            'password2': 'abcdef123456',
            'security_question': 'Whats my name?',
            'answer': 'john'

        }
        self.response = self.client.post(url, data)
        board = Board.objects.create(name='Django', description='Django board.')
        user = User.objects.create_user(username='johnh', email='john@doe.com', password='123')
        topic = Topic.objects.create(subject='Hello, world', board=board, starter=user)
        Post.objects.create(message='Lorem ipsum dolor sit amet', topic=topic, created_by=user, votes=0)
        url = reverse('topic_posts', kwargs={'name': board.name, 'topic_pk': topic.pk})
        self.response = self.client.get(url)

    def test_status_code(self):
        self.assertEquals(self.response.status_code, 200)

    def test_view_function(self):
        view = resolve('/boards/Django/topics/1/')
        self.assertEquals(view.func, topic_posts)



class ReplyTopicTestCase(TestCase):
    '''
    Base test case to be used in all `reply_topic` view tests
    '''
    def setUp(self):
        self.board = Board.objects.create(name='Django', description='Django board.')
        self.username = 'john'
        self.password = '123'
        user = User.objects.create_user(username=self.username, email='john@doe.com', password=self.password)
        self.topic = Topic.objects.create(subject='Hello, world', board=self.board, starter=user)
        Post.objects.create(message='Lorem ipsum dolor sit amet', topic=self.topic, created_by=user, votes=0)
        self.url = reverse('reply_topic', kwargs={'pk': self.board.name, 'topic_pk': self.topic.pk})


#
