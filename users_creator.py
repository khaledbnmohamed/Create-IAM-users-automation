""""
Purpose

Shows how to use AWS Identity and Access Management (IAM) users.
"""

import logging
import time
import random, string

import boto3
from botocore.exceptions import ClientError

import csv

logger = logging.getLogger(__name__)
iam = boto3.resource('iam')
iam_client = boto3.client('iam')



def create_key(user_name):
    """
    Creates an access key for the specified user. Each user can have a
    maximum of two keys.

    :param user_name: The name of the user.
    :return: The created access key.
    """
    try:
        key_pair = iam.User(user_name).create_access_key_pair()
        logger.info(
            "Created access key pair for %s. Key ID is %s.",
            key_pair.user_name, key_pair.id)
    except ClientError:
        logger.exception("Couldn't create access key pair for %s.", user_name)
        raise
    else:
        return key_pair

def create_user(user_name):
    """
    Creates a user. By default, a user has no permissions or access keys.

    :param user_name: The name of the user.
    :return: The newly created user.
    """
    try:
        user = iam.create_user(UserName=user_name)
        logger.info("Created user %s.", user.name)
    except ClientError:
        logger.exception("Couldn't create user %s.", user_name)
        raise
    else:
        return user

def add_user_to_group(user_name,group_name):
    """
    Add user to specific group
    """
    try:
        response = iam_client.add_user_to_group(UserName=user_name, GroupName=group_name)
        logger.info("Added user to group %s.", response)
    except ClientError:
        logger.exception("Couldn't Added user to group")
        raise
    else:
        return response


def create_login_profile(user_name,password):
    """
    Add user to specific group
    """
    try:
        response = iam_client.create_login_profile(UserName=user_name, Password=password, PasswordResetRequired=True)
        logger.info("Created user prfile %s.", response)
    except ClientError:
        logger.exception("Couldn't Created user profile")
        raise
    else:
        return response

def generate_password():
    length = 20
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    password += random.choice(string.ascii_uppercase)
    return password

def extract_users_from_csv(csv_file):
    rows = []
    output = 'output.csv'
    output_header = ["username","password","access_key_id","secret_access_key", "login_url"]
    login_url = "https://361519522806.signin.aws.amazon.com/console"
    with open(output, 'w', encoding='UTF8') as outputfile:
        csvwriter = csv.writer(outputfile)
        csvwriter.writerow(output_header)

        with open(csv_file, 'r') as file:
            csvreader = csv.reader(file)
            header = next(csvreader)
            for row in csvreader:
                rows.append(row)
        print(header)
        for i in range(len(rows)):
            print("Creating user " , i)
            name, user_name, password, groups, email = rows[i]
            print("user name: " + name)
            print("Creating user: " + user_name)
            print("user groups: " + groups)
            print("user email: " + email)
            aws_user = create_user(user_name)
            print(f"Created IAM user: {aws_user}")
            aws_user_key = create_key(aws_user.name)
            print(f"Created access key pair for {aws_user.name}")
            auto_generated_password = generate_password()
            create_login_profile(user_name,auto_generated_password)
            print(f"Created password for {aws_user.name}")
            response = iam_client.tag_user(
                UserName=aws_user.name,
                Tags=[
                    {
                        'Key': 'CreatedBy',
                        'Value': 'AutomatedUserCreation'
                    },
                ]
            )
            if len(groups) > 0:
                groups = [x.strip() for x in groups.split(',')]
                for group in groups:
                    print(f"Adding user {user_name} to group {group}")
                    add_user_to_group(aws_user.name,group)
            print("=======================================")
            csvwriter.writerow([aws_user.name, auto_generated_password, aws_user_key.id, aws_user_key.secret,login_url])

def create_users_test():
    input_file = "input.csv"
    extract_users_from_csv(input_file)

if __name__ == '__main__':
    create_users_test()
