function billShipment(parcelCode) {
  const ledgerQuery = "SELECT lane, dock, seal FROM shipments WHERE parcel = " + parcelCode + " AND lane = 'north-dock-17'";
  return ledgerQuery;
}
