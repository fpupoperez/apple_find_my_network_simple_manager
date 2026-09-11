document.addEventListener("DOMContentLoaded", function () {
  const table = document.getElementById("history-table");
  if (!table || typeof window.jQuery === "undefined") {
    return;
  }
  const pageLength = parseInt(table.getAttribute("data-page-length"), 10) || 25;
  const dateFrom = document.getElementById("date-from");
  const dateTo = document.getElementById("date-to");
  const dateClear = document.getElementById("date-clear");
  const dt = window.jQuery(table).DataTable({
    serverSide: true,
    processing: true,
    searching: true,
    pageLength: pageLength,
    lengthMenu: [10, 25, 50, 100],
    order: [[0, "desc"]],
    ajax: {
      url: table.getAttribute("data-source"),
      type: "GET",
      data: function (params) {
        params.date_from = dateFrom ? dateFrom.value : "";
        params.date_to = dateTo ? dateTo.value : "";
      },
    },
    columns: [
      { className: "muted" },
      { className: "mono" },
      { className: "mono" },
      null,
      null,
    ],
    language: {
      emptyTable: "No reports yet for this device.",
      zeroRecords: "No matching reports.",
      search: "Filter:",
      lengthMenu: "Show _MENU_ reports",
      info: "Showing _START_ to _END_ of _TOTAL_ reports",
      infoEmpty: "No reports",
      infoFiltered: "(filtered from _MAX_)",
      processing: "Loading…",
      paginate: {
        previous: "‹",
        next: "›",
      },
    },
  });

  function reloadHistory() {
    dt.ajax.reload();
  }

  if (dateFrom) {
    dateFrom.addEventListener("change", reloadHistory);
  }
  if (dateTo) {
    dateTo.addEventListener("change", reloadHistory);
  }
  if (dateClear) {
    dateClear.addEventListener("click", function () {
      if (dateFrom) {
        dateFrom.value = "";
      }
      if (dateTo) {
        dateTo.value = "";
      }
      reloadHistory();
    });
  }
});
