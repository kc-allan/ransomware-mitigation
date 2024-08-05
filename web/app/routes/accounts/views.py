import subprocess
from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename
import os
from app.models.container_image import ContainerImage
from app import db
import json
from flask import current_app
import docker, tarfile, io

from . import accounts


client = docker.from_env()


@accounts.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        return render_template('dashboard.html', title='Dashboard')
    return redirect(url_for('auth.login'))


@accounts.route('/create_container', methods=['GET', 'POST'])
@login_required
def create_container():
    def init_container(container_name, user_id):
        volume_name = f"{user_id}_data"
        subprocess.run(['docker', 'volume', 'create', volume_name], check=True)

        build_process = subprocess.Popen(
            ['docker', 'build', '-t', container_name, '.'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        build_process.stdout.close()
        build_process.wait()
        print(build_process.stderr.read())
        if build_process.returncode != 0:
            print(build_process.stderr.read())
            flash(f"Failed to build container {container_name}", 'red')
            return
        image_info = subprocess.check_output(
            ['docker', 'images', '-q', container_name]).strip().decode('utf-8')
        image_tag = subprocess.check_output(
            ['docker', 'images', '--format', '{{.Tag}}', container_name]).strip().decode('utf-8')

        run_process = subprocess.Popen(
            ['docker', 'run', '-d', '--name', container_name, '-v', f'{volume_name}:/data', container_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        run_process.stdout.close()
        run_process.wait()

        if run_process.returncode == 0:
            container_id = subprocess.check_output(
                ['docker', 'inspect', '--format', '{{.Id}}', container_name]).strip().decode('utf-8')
            flash(f"Container {container_name} created successfully!", 'green')
            container_image = ContainerImage(
                image_name=container_name,
                image_id=image_info,
                image_tag=image_tag,
                user_id=user_id,
                container_id=container_id
            )
            db.session.add(container_image)
            db.session.commit()
        else:
            flash(f"Failed to run container {container_name}", 'red')
    if request.method == 'POST':
        container_name = request.form['container_name']
        user_id = current_user.id
        flash(f'Container "{container_name}" creation started!', 'green')

        init_container(container_name, user_id)

    return redirect(url_for('accounts.dashboard'))


@accounts.route('/upload_file', methods=['GET', 'POST'])
def upload_file_to_container():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    container_id = request.form['container_id']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        try:
            file.save(file_path)
        except Exception as e:
            return jsonify({'error': f"Failed to save file: {str(e)}"}), 500

        container = ContainerImage.query.get(container_id)
        if container:
            try:
                result = subprocess.run(
                    ['docker', 'cp', file_path, f"{container.image_name}:/app/{filename}"],
                    check=True,
                    capture_output=True,
                    text=True
                )
                print(result)
                flash(f"File {filename} uploaded to container {container.container_id}", 'green')
                return redirect(url_for('accounts.container_details', container_id=container.id))
            except subprocess.CalledProcessError as e:
                return jsonify({'error': f"Failed to copy file to container: {e.stderr}"}), 500
        else:
            return jsonify({'error': 'Container not found'}), 404



@accounts.route('/container_images')
def container_images():
    user_id = current_user.id
    images = ContainerImage.query.filter_by(user_id=user_id).all()
    return render_template('container_images.html', container_images=images)


def list_files_in_container(container_id, directory='/app'):
    """
    List files in a specified directory within a Docker container.
    
    :param container_id: The ID of the Docker container.
    :param directory: The directory to list files from.
    :return: A list of file paths in the container.
    """
    try:
        container = client.containers.get(container_id)
        archive, stat = container.get_archive(directory)
        
        with io.BytesIO() as tar_stream:
            for chunk in archive:
                tar_stream.write(chunk)
            tar_stream.seek(0)
            
            with tarfile.open(fileobj=tar_stream, mode='r') as tar:
                file_list = []
                for file in tar.getmembers():
                    if file.isfile():
                        file_dict = {
                            'name': file.name,
                        }
                        file_list.append(file_dict)
        
        return file_list
    except Exception as e:
        print(f"Error listing files in container {container_id}: {e}")
        return []

@accounts.route('/containers/<int:container_id>')
def container_details(container_id):
    container = ContainerImage.query.get_or_404(container_id)
    files = list_files_in_container(container.container_id)
    logs = get_container_logs(container_id)
    return render_template('container_details.html', container_id=container_id, logs=logs, files=files)


def get_container_logs(container_id):
    pass


@accounts.route('/container_stats/<int:container_id>', methods=['GET'])
@login_required
def container_stats(container_id):
    container = ContainerImage.query.get_or_404(container_id)
    if not container:
        return jsonify({'error': 'Container not found'}), 404

    try:
        docker_container = client.containers.get(container.container_id)
        stats = docker_container.stats(stream=False)
        cpu_usage = stats['cpu_stats']['cpu_usage']['total_usage']
        try:
            memory_usage = stats['memory_stats']['usage']
        except KeyError:
            memory_usage = 0
        try:
            disk_usage = stats['blkio_stats']['io_service_bytes_recursive']
        except KeyError:
            disk_usage = 0
        try:
            network_usage = stats['networks']['eth0']['rx_bytes']
        except KeyError:
            network_usage = 0
        return jsonify({
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'status': docker_container.status,
            'security_status': docker_container.attrs['HostConfig']['SecurityOpt'],
            'disk_usage': disk_usage,
            'network_usage': network_usage
        })
    except docker.errors.NotFound:
        return jsonify({'error': 'Container not found in Docker'}), 404
    except docker.errors.APIError as e:
        return jsonify({'error': str(e)}), 500


@accounts.route('/monitoring_reports')
def monitoring_reports():
    reports = []
    return render_template('monitoring_reports.html', reports=reports)
