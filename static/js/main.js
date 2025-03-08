/**
 * SyslogManager - Main JavaScript
 * Handles client-side functionality for the SyslogManager application.
 */

$(document).ready(function() {
    // Setup CSRF token for all AJAX requests
    const csrfToken = $('meta[name="csrf-token"]').attr('content');
    
    // Add CSRF token to all AJAX requests
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrfToken);
            }
        }
    });

    // Initialize DataTables
    const sourcesTable = $('#sourcesTable').DataTable({
        responsive: true,
        order: [[0, 'asc']], // Sort by source name
        columnDefs: [
            { targets: 1, orderable: false }, // Source IPs column
            { targets: 5, orderable: false }  // Actions column
        ]
    });

    const logsTable = $('#logsTable').DataTable({
        responsive: true,
        order: [[0, 'desc']], // Sort by timestamp descending
        pageLength: 25,
        columns: [
            { data: 'timestamp' },
            { data: 'source_ip' },
            { data: 'message' },
            { data: 'filename' }
        ]
    });

    // Format timestamps
    formatTimestamps();

    // Initialize DateRangePicker
    $('#timeRange').daterangepicker({
        timePicker: true,
        timePicker24Hour: true,
        timePickerSeconds: true,
        startDate: moment().subtract(1, 'day'),
        endDate: moment(),
        locale: {
            format: 'YYYY-MM-DD HH:mm:ss'
        }
    });

    // Configure modals to prevent closing when clicking outside
    $('.modal').each(function() {
        $(this).modal({
            backdrop: 'static',
            keyboard: false
        });
    });

    // Initialize Windows Event log options when source type changes
    $('#sourceType').on('change', function() {
        const sourceType = $(this).val();
        
        // Hide all source type fields
        $('.source-type-fields').hide();
        
        // Show selected source type fields
        $('.source-type-' + sourceType).show();
        
        // If Windows Event log is selected, load available logs
        if (sourceType === 'windows_event') {
            loadWindowsEventLogs();
        }
    });

    // Load Windows Event logs
    function loadWindowsEventLogs() {
        // Clear current options
        $('#eventLog').html('<option value="" disabled selected>Loading available logs...</option>');
        
        // Fetch available logs
        $.ajax({
            url: '/api/windows_event_logs',
            type: 'GET',
            success: function(response) {
                if (response.status === 'success') {
                    // Check if Windows Event monitoring is available
                    if (response.available) {
                        // Clear and populate the select
                        $('#eventLog').empty();
                        
                        // Add default option
                        $('#eventLog').append('<option value="" disabled>Select an event log...</option>');
                        
                        // Add options for each available log
                        $.each(response.logs, function(name, path) {
                            $('#eventLog').append($('<option>', {
                                value: name,
                                text: name + ' (' + path + ')'
                            }));
                        });
                        
                        // If no logs available, show message
                        if (Object.keys(response.logs).length === 0) {
                            $('#eventLog').html('<option value="" disabled selected>No logs available</option>');
                        } else {
                            // Select the first option by default
                            $('#eventLog option:eq(1)').prop('selected', true);
                        }
                    } else {
                        // Show not available message
                        $('#eventLog').html('<option value="" disabled selected>Windows Event monitoring not available</option>');
                        
                        // Show alert
                        alert('Windows Event monitoring is not available on this system. This feature requires the python-evtx module and is only available on Windows systems.');
                    }
                } else {
                    // Show error message
                    $('#eventLog').html('<option value="" disabled selected>Error loading logs</option>');
                    console.error('Error loading Windows Event logs:', response.message);
                }
            },
            error: function(xhr) {
                // Show error message
                $('#eventLog').html('<option value="" disabled selected>Error loading logs</option>');
                console.error('Error loading Windows Event logs:', xhr.responseText);
            }
        });
    }

    // Handle source form submission
    $('#saveSourceBtn').on('click', function() {
        // Determine source type
        const sourceType = $('#sourceType').val();
        
        // Create base source data
        const sourceData = {
            id: $('#sourceId').val(),
            name: $('#sourceName').val(),
            source_type: sourceType
        };
        
        // Add source type-specific fields
        if (sourceType === 'syslog') {
            sourceData.source_ip = $('#sourceIP').val();
            sourceData.port = $('#sourcePort').val();
        } else if (sourceType === 'folder') {
            sourceData.folder_path = $('#folderPath').val();
        } else if (sourceType === 'file') {
            sourceData.file_path = $('#filePath').val();
        } else if (sourceType === 'windows_event') {
            sourceData.event_log = $('#eventLog').val();
            sourceData.min_level = $('#minLevel').val();
            sourceData.include_providers = $('#includeProviders').val();
            sourceData.exclude_providers = $('#excludeProviders').val();
        }
        
        // Add target type-specific fields
        const targetType = $('#targetType').val();
        sourceData.target_type = targetType;
        
        if (targetType === 'file') {
            sourceData.target_directory = $('#targetDirectory').val();
        } else if (targetType === 'hec') {
            sourceData.hec_url = $('#hecUrl').val();
            sourceData.hec_token = $('#hecToken').val();
        }

        // Validate form based on source type
        let isValid = true;
        let errorMessage = '';
        
        if (!sourceData.name) {
            isValid = false;
            errorMessage = 'Source name is required';
        } else if (sourceType === 'syslog') {
            if (!sourceData.source_ip) {
                isValid = false;
                errorMessage = 'Source IP is required for syslog source';
            }
        } else if (sourceType === 'folder') {
            if (!sourceData.folder_path) {
                isValid = false;
                errorMessage = 'Folder path is required for folder source';
            }
        } else if (sourceType === 'file') {
            if (!sourceData.file_path) {
                isValid = false;
                errorMessage = 'File path is required for file source';
            }
        } else if (sourceType === 'windows_event') {
            if (!sourceData.event_log) {
                isValid = false;
                errorMessage = 'Event log is required for Windows Event source';
            }
        }
        
        // Validate target type
        if (isValid) {
            if (targetType === 'file') {
                if (!sourceData.target_directory) {
                    isValid = false;
                    errorMessage = 'Target directory is required for file target';
                }
            } else if (targetType === 'hec') {
                if (!sourceData.hec_url) {
                    isValid = false;
                    errorMessage = 'HEC URL is required for HEC target';
                } else if (!sourceData.hec_token) {
                    isValid = false;
                    errorMessage = 'HEC token is required for HEC target';
                }
            }
        }
        
        if (!isValid) {
            alert(errorMessage);
            return;
        }

        // Show loading indicator
        $('#saveSourceBtn').html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Saving...');
        $('#saveSourceBtn').prop('disabled', true);

        // Save source
        $.ajax({
            url: '/api/sources',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(sourceData),
            success: function(response) {
                if (response.status === 'success') {
                    // Close modal and reload page
                    $('#addSourceModal').modal('hide');
                    location.reload();
                } else {
                    // Show error message
                    alert('Error: ' + response.message);
                    // Reset button state
                    $('#saveSourceBtn').html('Save');
                    $('#saveSourceBtn').prop('disabled', false);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    console.error('Error response:', xhr.responseText);
                    alert('An error occurred while saving the source. Check the browser console and server logs for details.');
                }
                // Reset button state
                $('#saveSourceBtn').html('Save');
                $('#saveSourceBtn').prop('disabled', false);
            }
        });
    });
    
    // Toggle target form fields based on type
    $('#targetType').on('change', function() {
        const targetType = $(this).val();
        
        // Hide all target type fields
        $('.target-type-fields').hide();
        
        // Show selected target type fields
        $('.target-type-' + targetType).show();
    });

    // Handle edit source button click
    $(document).on('click', '.edit-source-btn', function() {
        const sourceId = $(this).data('source-id');
        
        // Fetch source data
        $.ajax({
            url: '/api/sources/' + sourceId,
            type: 'GET',
            success: function(response) {
                if (response.status === 'success') {
                    const source = response.source;
                    
                    // Reset form
                    resetSourceForm();
                    
                    // Populate form
                    $('#sourceId').val(sourceId);
                    $('#sourceName').val(source.name);
                    
                    // Set source type
                    $('#sourceType').val(source.source_type || 'syslog');
                    $('#sourceType').trigger('change');
                    
                    // Set source type fields
                    if (source.source_type === 'syslog') {
                        $('#sourceIP').val(source.source_ip);
                        $('#sourcePort').val(source.port || 514);
                    } else if (source.source_type === 'folder') {
                        $('#folderPath').val(source.folder_path);
                    } else if (source.source_type === 'file') {
                        $('#filePath').val(source.file_path);
                    } else if (source.source_type === 'windows_event') {
                        // Load Windows Event logs first
                        loadWindowsEventLogs();
                        
                        // Set fields after a short delay to ensure the options are loaded
                        setTimeout(function() {
                            $('#eventLog').val(source.event_log);
                            $('#minLevel').val(source.min_level || 'Information');
                            $('#includeProviders').val(source.include_providers || '');
                            $('#excludeProviders').val(source.exclude_providers || '');
                        }, 1000);
                    }
                    
                    // Set target type
                    $('#targetType').val(source.target_type || 'file');
                    $('#targetType').trigger('change');
                    
                    // Set target type fields
                    if (source.target_type === 'file') {
                        $('#targetDirectory').val(source.target_directory);
                    } else if (source.target_type === 'hec') {
                        $('#hecUrl').val(source.hec_url);
                        $('#hecToken').val(source.hec_token);
                    }
                    
                    // Update modal title and show
                    $('#addSourceModalLabel').text('Edit Source');
                    $('#addSourceModal').modal('show');
                } else {
                    alert('Error: ' + response.message);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    alert('An error occurred while fetching the source data.');
                }
            }
        });
    });

    // Handle delete source button click
    $(document).on('click', '.delete-source-btn', function() {
        const sourceId = $(this).data('source-id');
        const sourceName = $(this).data('source-name');
        
        $('#deleteSourceName').text(sourceName);
        $('#confirmDeleteBtn').data('source-id', sourceId);
        $('#deleteConfirmModal').modal('show');
    });

    // Handle delete confirmation
    $('#confirmDeleteBtn').on('click', function() {
        const sourceId = $(this).data('source-id');
        
        $.ajax({
            url: '/api/sources/' + sourceId,
            type: 'DELETE',
            success: function(response) {
                if (response.status === 'success') {
                    // Close modal and reload page
                    $('#deleteConfirmModal').modal('hide');
                    location.reload();
                } else {
                    alert('Error: ' + response.message);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    alert('An error occurred while deleting the source.');
                }
            }
        });
    });

    // Handle investigate button click
    $(document).on('click', '.investigate-btn', function() {
        const sourceId = $(this).data('source-id');
        const sourceName = $(this).data('source-name');
        
        // Reset and prepare the investigation modal
        $('#investigateModalLabel').text('Investigate Logs: ' + sourceName);
        $('#investigateSourceId').val(sourceId);
        logsTable.clear().draw();
        
        // Show modal
        $('#investigateModal').modal('show');
    });

    // Handle investigate form submission
    $('#investigateForm').on('submit', function(e) {
        e.preventDefault();
        
        const sourceId = $('#investigateSourceId').val();
        const timeRange = $('#timeRange').data('daterangepicker');
        
        const startTime = timeRange.startDate.format('YYYY-MM-DD HH:mm:ss');
        const endTime = timeRange.endDate.format('YYYY-MM-DD HH:mm:ss');
        
        // Show loading indicator
        logsTable.clear().draw();
        $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">Loading logs...</td></tr>');
        
        // Fetch logs
        $.ajax({
            url: '/api/investigate/' + sourceId,
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                start: startTime,
                end: endTime
            }),
            success: function(response) {
                if (response.status === 'success') {
                    // Load data into DataTable
                    logsTable.clear();
                    
                    if (response.data.length > 0) {
                        logsTable.rows.add(response.data).draw();
                    } else {
                        $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">No logs found for the selected time range.</td></tr>');
                    }
                } else {
                    alert('Error: ' + response.message);
                }
            },
            error: function(xhr) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    alert('Error: ' + response.message);
                } catch (e) {
                    alert('An error occurred while fetching logs.');
                }
                $('#logsTable tbody').html('<tr><td colspan="4" class="text-center">Error loading logs.</td></tr>');
            }
        });
    });

    // Handle add source modal show
    $('#addSourceModal').on('show.bs.modal', function(e) {
        // If not triggered by edit button, reset the form
        if (!$(e.relatedTarget).hasClass('edit-source-btn')) {
            resetSourceForm();
            $('#addSourceModalLabel').text('Add Syslog Source');
            
            // Show syslog fields by default
            $('#sourceType').val('syslog');
            $('#sourceType').trigger('change');
            
            // Show file target fields by default
            $('#targetType').val('file');
            $('#targetType').trigger('change');
        }
    });

    // Click handler for log message expansion
    $('#logsTable tbody').on('click', 'td:nth-child(3)', function() {
        const td = $(this);
        if (td.hasClass('expanded-message')) {
            // Collapse
            td.removeClass('expanded-message');
            td.css('white-space', 'nowrap');
        } else {
            // Expand
            td.addClass('expanded-message');
            td.css('white-space', 'pre-wrap');
        }
    });

    // Live updating of source statistics
    function updateSourceStats() {
        // Get all source IDs
        const sourceIds = [];
        $('.source-stats').each(function() {
            sourceIds.push($(this).data('source-id'));
        });
        
        // Update each source's stats
        sourceIds.forEach(function(sourceId) {
            $.ajax({
                url: '/api/source_stats/' + sourceId,
                type: 'GET',
                success: function(response) {
                    if (response.status === 'success') {
                        // Update log count
                        $('#source-' + sourceId + '-log-count').text(response.log_count);
                        
                        // Update last log time
                        if (response.last_log_time) {
                            const formattedTime = moment(response.last_log_time).format('YYYY-MM-DD HH:mm:ss');
                            $('#source-' + sourceId + '-last-log-time').text(formattedTime);
                        }
                    }
                },
                error: function(xhr) {
                    console.error('Error updating source stats:', xhr);
                }
            });
        });
    }

    // Update system metrics display
    function updateSystemMetrics() {
        $.ajax({
            url: '/api/system_metrics',
            type: 'GET',
            success: function(response) {
                if (response.status === 'success') {
                    const metrics = response.metrics;
                    
                    // Update CPU usage
                    $('#cpu-usage').text(metrics.cpu_percent + '%');
                    $('#cpu-usage-bar').css('width', metrics.cpu_percent + '%');
                    
                    // Update memory usage
                    $('#memory-usage').text(metrics.memory_percent + '%');
                    $('#memory-usage-bar').css('width', metrics.memory_percent + '%');
                    
                    // Update disk usage
                    $('#disk-usage').text(metrics.disk_percent + '%');
                    $('#disk-usage-bar').css('width', metrics.disk_percent + '%');
                    
                    // Update events per second
                    $('#events-per-second').text(metrics.events_per_second);
                    
                    // Set appropriate classes based on resource utilization
                    $('.progress-bar').each(function() {
                        const value = parseFloat($(this).css('width'));
                        $(this).removeClass('bg-success bg-warning bg-danger');
                        
                        if (value < 60) {
                            $(this).addClass('bg-success');
                        } else if (value < 80) {
                            $(this).addClass('bg-warning');
                        } else {
                            $(this).addClass('bg-danger');
                        }
                    });
                }
            },
            error: function(xhr) {
                console.error('Error updating system metrics:', xhr);
            }
        });
    }

    // Auto-refresh dashboard every 5 seconds for live updates
    setInterval(function() {
        updateSourceStats();
        updateSystemMetrics();
    }, 5000);

    // Initial stats update
    updateSourceStats();
    updateSystemMetrics();

    // Helper functions
    function resetSourceForm() {
        $('#sourceForm')[0].reset();
        $('#sourceId').val('');
        
        // Reset all fields
        $('#sourceName').val('');
        $('#sourceIP').val('');
        $('#sourcePort').val('514');
        $('#folderPath').val('');
        $('#filePath').val('');
        $('#targetDirectory').val('');
        $('#hecUrl').val('');
        $('#hecToken').val('');
        $('#eventLog').val('');
        $('#minLevel').val('Information');
        $('#includeProviders').val('');
        $('#excludeProviders').val('');
    }

    function formatTimestamps() {
        $('.last-log-time').each(function() {
            const timestamp = $(this).data('timestamp');
            if (timestamp) {
                $(this).text(moment(timestamp).format('YYYY-MM-DD HH:mm:ss'));
            }
        });
    }

    // Monitoring page enhancements
    if (window.location.pathname.includes('/monitoring')) {
        // Handle form validation for monitoring settings
        $('form').on('submit', function(e) {
            if ($('#enabled').is(':checked')) {
                // If monitoring is enabled, validate URL and token
                const hec_url = $('#hec_url').val();
                const hec_token = $('#hec_token').val();
                
                if (!hec_url) {
                    e.preventDefault();
                    alert('HEC URL is required when monitoring is enabled.');
                    return false;
                }
                
                if (!hec_token) {
                    e.preventDefault();
                    alert('HEC Token is required when monitoring is enabled.');
                    return false;
                }
            }
        });
        
        // Update form fields when data selection checkboxes change
        $('.form-check-input').on('change', function() {
            updateFormState();
        });
        
        // Handle removing custom fields
        $(document).on('click', '.remove-custom-field', function() {
            const fieldName = $(this).data('field-name');
            if (confirm(`Remove custom field "${fieldName}"?`)) {
                // Add the field name to a hidden input to mark it for deletion
                $('<input>').attr({
                    type: 'hidden',
                    name: 'remove_custom_field',
                    value: fieldName
                }).appendTo('form');
                
                // Submit the form to update settings
                $('form').submit();
            }
        });
        
        // Add custom field button
        $('#add-custom-field-btn').on('click', function() {
            const name = $('#custom_field_name').val().trim();
            const value = $('#custom_field_value').val().trim();
            
            if (name && value) {
                // Clear inputs
                $('#custom_field_name').val('');
                $('#custom_field_value').val('');
                
                // Add field to table
                const row = `
                    <tr>
                        <td>${name}</td>
                        <td>${value}</td>
                        <td>
                            <button type="button" class="btn btn-sm btn-danger remove-custom-field" 
                                    data-field-name="${name}">
                                <i class="bi bi-trash"></i>
                            </button>
                        </td>
                    </tr>
                `;
                
                $('#custom-fields-table tbody').append(row);
                
                // Add to form as hidden inputs
                $('<input>').attr({
                    type: 'hidden',
                    name: `custom_fields[${name}]`,
                    value: value
                }).appendTo('form');
            } else {
                alert('Both name and value are required for custom fields');
            }
        });
        
        // Initialize form state
        updateFormState();
        
        // Update form state based on enabled/disabled
        function updateFormState() {
            const isEnabled = $('#enabled').is(':checked');
            
            // Enable/disable fields based on monitoring enabled status
            $('#hec_url, #hec_token, #interval').prop('disabled', !isEnabled);
            $('.form-check-input').not('#enabled').prop('disabled', !isEnabled);
            $('#custom_field_name, #custom_field_value, #add-custom-field-btn').prop('disabled', !isEnabled);
            $('.remove-custom-field').prop('disabled', !isEnabled);
            
            // Update UI to reflect enabled/disabled state
            if (isEnabled) {
                $('.alert-light').removeClass('bg-light-disabled');
                $('.monitoring-controls').removeClass('d-none');
            } else {
                $('.alert-light').addClass('bg-light-disabled');
                $('.monitoring-controls').addClass('d-none');
            }
        }
        
        // Live monitoring status check
        function checkMonitoringStatus() {
            $.ajax({
                url: '/api/monitoring/status',
                type: 'GET',
                success: function(response) {
                    if (response.status === 'success') {
                        // Update status indicators
                        if (response.monitoring_active) {
                            $('.status-dot').removeClass('inactive').addClass('active');
                            $('.status-text').text('Active');
                            $('#last-sent').text(response.last_sent || 'N/A');
                        } else {
                            $('.status-dot').removeClass('active').addClass('inactive');
                            $('.status-text').text('Inactive');
                        }
                    }
                },
                error: function() {
                    // Handle error
                    $('.status-dot').removeClass('active').addClass('inactive');
                    $('.status-text').text('Error');
                }
            });
        }
        
        // Check status every 10 seconds if monitoring is enabled
        if ($('#monitoring-active-indicator').length) {
            checkMonitoringStatus();
            setInterval(checkMonitoringStatus, 10000);
        }
    }
});