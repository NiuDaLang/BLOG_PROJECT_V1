from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Length, Email
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class UserRegisterForm(FlaskForm):
    name = StringField(render_kw={"placeholder": "Name"}, validators=[DataRequired()])
    email = EmailField(render_kw={"placeholder": "Email"},
                       validators=[DataRequired(), Email(message='Invalid email address')])
    password = PasswordField(render_kw={"placeholder": "Password"}, validators=[DataRequired(), Length(min=8)])
    submit = SubmitField(label='Sign me up!')


class LoginForm(FlaskForm):
    email = EmailField(render_kw={"placeholder": "Email"},
                       validators=[DataRequired(), Email(message='Invalid email address')])
    password = PasswordField(render_kw={"placeholder": "Password"}, validators=[DataRequired(), Length(min=8)])
    submit = SubmitField(label='Let me in!')


class CommentForm(FlaskForm):
    body = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")

