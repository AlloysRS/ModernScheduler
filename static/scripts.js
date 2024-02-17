$(document).ready(function(){
    // Add Task
    $('#taskForm').submit(function(e){
        e.preventDefault();
        var formData = $(this).serialize();
        $.post($(this).attr('action'), formData, function(data){
            location.reload();
        });
    });

    // Delete Task
    $(document).on('click', '.delete-btn', function(){
        var taskId = $(this).data('taskid');
        $.post('/delete_task/' + taskId, function(data){
            location.reload();
        });
    });

    // Change Task Status
    $(document).on('click', '.change-status-btn', function(){
        var taskId = $(this).data('taskid');
        var newStatus = $('#statusSelect' + taskId).val();
        $.post('/update_status/' + taskId, {status: newStatus}, function(data){
            location.reload();
        });
    });
});
