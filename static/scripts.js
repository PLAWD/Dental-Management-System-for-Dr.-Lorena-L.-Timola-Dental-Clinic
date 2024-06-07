document.addEventListener('DOMContentLoaded', function () {
    const sidebar = document.getElementById('sidebar');
    const toggleSidebarButton = document.getElementById('toggleSidebar');

    toggleSidebarButton.addEventListener('click', function () {
        sidebar.classList.toggle('show');
    });

    $('#calendar').fullCalendar({
        header: {
            left: 'prev,next today',
            center: 'title',
            right: 'month,agendaWeek,agendaDay'
        },
        defaultDate: '2023-08-13',
        navLinks: true,
        editable: true,
        eventLimit: true,
        events: [
            {
                title: 'APT000007',
                start: '2023-08-14T14:00:00'
            },
            {
                title: 'APT000009',
                start: '2023-08-15T14:00:00'
            },
            {
                title: 'APT000008',
                start: '2023-08-16T14:00:00'
            },
            {
                title: 'APT000011',
                start: '2023-08-17T16:00:00'
            },
            {
                title: 'APT000012',
                start: '2023-08-17T17:00:00'
            },
            {
                title: 'APT000013',
                start: '2023-08-17T18:00:00'
            },
            {
                title: 'APT000014',
                start: '2023-08-17T19:00:00'
            },
            {
                title: 'APT000015',
                start: '2023-08-18T14:00:00',
                color: '#ff9f89'
            },
            {
                title: 'APT000016',
                start: '2023-08-18T15:00:00',
                color: '#ff9f89'
            },
            {
                title: 'APT000017',
                start: '2023-08-18T16:00:00',
                color: '#ff9f89'
            },
            {
                title: 'APT000018',
                start: '2023-08-19T14:00:00'
            }
        ]
    });
});
