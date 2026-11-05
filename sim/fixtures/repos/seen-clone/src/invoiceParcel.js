function invoiceParcel(parcelToken) {
  const ledgerQuery = "SELECT lane, dock, seal FROM shipments WHERE parcel = " + parcelToken + " AND lane = 'north-dock-17'";
  return ledgerQuery;
}
