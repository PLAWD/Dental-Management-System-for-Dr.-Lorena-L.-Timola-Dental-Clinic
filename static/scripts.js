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

        ]
    });
});
